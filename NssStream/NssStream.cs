namespace NssSsl;

using System.Buffers;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

public sealed partial class NssStream : Stream
{
    // Presets matching a real Firefox ClientHello (captured via
    // https://tls.peet.ws/api/tls, see .tmp/tls.peet.ws.txt):
    //
    // ja3:  771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-
    //       49171-49172-156-157-47-53,
    //       0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,
    //       4588-29-23-24-25-256-257,0
    // ja4:  t13d1617h2_86a278354501_3cbfd9057e0d
    //
    // The TLS 1.3 suites (TLS_AES_* / TLS_CHACHA20_*) are always enabled
    // by NSS and are therefore not part of the cipher list below; the
    // ClientHello order follows NSS's implementation order, which matches
    // Firefox.
    public const string FirefoxCipherSuitePreset =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
        "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:" +
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
    public const int FirefoxEnableGreasePreset = 0;
    public const int FirefoxEnableEchGreasePreset = 1;
    public const string FirefoxAlpnPreset = "h2:http/1.1";
    public const string FirefoxAlpsPreset = "";
    public const string FirefoxTrustAnchorsPreset = "";
    public const string FirefoxSignatureAlgorithmsPreset =
        "ECDSA-SECP256R1-SHA256:ECDSA-SECP384R1-SHA384:ECDSA-SECP521R1-SHA512:" +
        "RSA-PSS-RSAE-SHA256:RSA-PSS-RSAE-SHA384:RSA-PSS-RSAE-SHA512:" +
        "RSA-PKCS1-SHA256:RSA-PKCS1-SHA384:RSA-PKCS1-SHA512:" +
        "ECDSA-SHA1:RSA-PKCS1-SHA1";
    public const int FirefoxEnableSignedCertTimestampsPreset = 1;
    public const int FirefoxSetOcspStatusTypePreset = 1;
    public const int FirefoxEnableBrotliPreset = 1;

    private const int NetworkBufferSize = 16 * 1024;

    private readonly Stream _innerStream;
    private string _hostname;
    private readonly bool _leaveOpen;
    private Native.SslHandle _connection = new();

    // Parameters captured for the native connection factory, so the
    // connection can be re-created when SslClientAuthenticationOptions
    // override the constructor defaults before the handshake starts.
    private readonly string _cipherList;
    private readonly int _enableGrease;
    private readonly int _enableEchGrease;
    private string _alpnProtos;
    private readonly string _alpsProtos;
    private readonly string _trustAnchors;
    private readonly string _sigAlgs;
    private readonly int _enableSignedCertTimestamps;
    private readonly int _setOcspStatusType;
    private readonly int _enableBrotli;

    // SslClientAuthenticationOptions-compatible managed validation.
    private RemoteCertificateValidationCallback? _sslValidationCallback;

    // X509RevocationMode.Online is not supported on macOS: the platform chain
    // builder cannot fetch CRL/OCSP data on demand and the chain build fails
    // with "An incomplete certificate revocation check occurred"
    // (CRYPT_E_NO_REVOCATION_CHECK). Downgrade to NoCheck there so the OS
    // trust store decision still applies.
    private static X509RevocationMode NormalizeRevocationMode(X509RevocationMode mode) =>
        OperatingSystem.IsMacOS() && mode == X509RevocationMode.Online
            ? X509RevocationMode.NoCheck
            : mode;

    private X509RevocationMode _revocationMode = OperatingSystem.IsMacOS()
        ? X509RevocationMode.NoCheck
        : X509RevocationMode.Online;

    // SSL* is not accessed concurrently.
    private readonly SemaphoreSlim _readLock = new(1, 1);
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // SSL* is not thread-safe. Every native call is short and non-blocking
    // (memory BIOs only), so a plain monitor is enough. Never await inside it.
    // It also keeps the thread-local native error valid: the call and
    // GetNativeError() happen on the same thread with no await in between.
    private readonly object _nativeSync = new();


    // ---- Write pump -------------------------------------------------
    // Only the pump moves bytes from the NSS write BIO to the inner
    // stream, so the order of TLS records is preserved without any network
    // write lock, and a reader never has to wait for a blocked socket write.
    private readonly byte[] _pumpBuffer =
        GC.AllocateArray<byte>(NetworkBufferSize, pinned: true);

    private readonly Channel<bool> _flushSignal =
        Channel.CreateBounded<bool>(
            new BoundedChannelOptions(1)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true
            });

    private readonly List<TaskCompletionSource> _flushWaiters = new();
    private readonly CancellationTokenSource _pumpCts = new();
    private Task? _pumpTask;
    private Exception? _pumpError;
    private bool _pumpStopped; // guarded by _flushWaiters

    private bool _authenticated;
    private bool _disposed;

    /// <summary>
    /// Optional replacement for the built-in server certificate validation
    /// (X509Chain + hostname match). Intended for tests that use self-signed
    /// certificates. Leave null in production code.
    /// </summary>
    public Func<X509Certificate2, bool>? RemoteCertificateValidationCallback { get; set; }

    public NssStream(
        Stream innerStream,
        string hostname,
        string cipherList = FirefoxCipherSuitePreset,
        int enableGrease = FirefoxEnableGreasePreset,
        int enableEchGrease = FirefoxEnableEchGreasePreset,        
        string alpnProtos = FirefoxAlpnPreset,
        string alpsProtos = FirefoxAlpsPreset,
        string trustAnchors = FirefoxTrustAnchorsPreset,
        string sigAlgs = FirefoxSignatureAlgorithmsPreset,
        int enableSignedCertTimestamps = FirefoxEnableSignedCertTimestampsPreset,
        int setOcspStatusType = FirefoxSetOcspStatusTypePreset,
        int enableBrotli = FirefoxEnableBrotliPreset,
        bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);

        _innerStream = innerStream;
        _hostname = hostname;
        _leaveOpen = leaveOpen;

        _cipherList = cipherList;
        _enableGrease = enableGrease;
        _enableEchGrease = enableEchGrease;
        _alpnProtos = alpnProtos;
        _alpsProtos = alpsProtos;
        _trustAnchors = trustAnchors;
        _sigAlgs = sigAlgs;
        _enableSignedCertTimestamps = enableSignedCertTimestamps;
        _setOcspStatusType = setOcspStatusType;
        _enableBrotli = enableBrotli;

        var connection = CreateConnection(hostname, alpnProtos);

        Marshal.InitHandle(_connection, connection);
    }

    private IntPtr CreateConnection(string hostname, string alpnProtos)
    {
        var connection = Native.pms_ssl_create(
            hostname,
            _cipherList,
            _enableGrease,
            _enableEchGrease,
            alpnProtos,
            _alpsProtos,
            _trustAnchors,
            _sigAlgs,
            _enableSignedCertTimestamps,
            _setOcspStatusType,
            _enableBrotli);

        if (connection == IntPtr.Zero)
        {
            throw new IOException(
                $"Failed to create NSS connection: " +
                $"{GetNativeError()}");
        }

        return connection;
    }

    /// <summary>
    /// Re-creates the native SSL connection with a new target host and/or
    /// ALPN list. Only allowed before the handshake has started.
    /// </summary>
    private void RecreateConnection(string hostname, string alpnProtos)
    {
        if (_pumpTask is not null || _authenticated)
        {
            throw new InvalidOperationException(
                "SSL options can only be applied before the handshake starts.");
        }

        _connection.Dispose();

        var handle = new Native.SslHandle();
        Marshal.InitHandle(handle, CreateConnection(hostname, alpnProtos));

        _hostname = hostname;
        _alpnProtos = alpnProtos;
        _connection = handle;
    }

    /// <summary>
    /// SslStream-compatible overload. Maps a subset of
    /// SslClientAuthenticationOptions onto NssStream:
    /// TargetHost and ApplicationProtocols (re-creates the native
    /// connection), RemoteCertificateValidationCallback and
    /// CertificateRevocationCheckMode (managed validation).
    /// </summary>
    public ValueTask AuthenticateAsClientAsync(
        SslClientAuthenticationOptions? clientOptions,
        CancellationToken cancellationToken = default)
    {
        if (clientOptions is not null)
        {
            ApplyClientOptions(clientOptions);
        }

        return AuthenticateAsClientAsync(cancellationToken);
    }

    private void ApplyClientOptions(SslClientAuthenticationOptions options)
    {
        if (_pumpTask is not null || _authenticated)
        {
            throw new InvalidOperationException(
                "SSL options can only be applied before the handshake starts.");
        }

        string hostname = _hostname;
        if (!string.IsNullOrEmpty(options.TargetHost) &&
            !string.Equals(options.TargetHost, _hostname, StringComparison.OrdinalIgnoreCase))
        {
            hostname = options.TargetHost;
        }

        string alpnProtos = _alpnProtos;
        if (options.ApplicationProtocols is { Count: > 0 } applicationProtocols)
        {
            alpnProtos = string.Join(":", applicationProtocols.Select(p => Encoding.UTF8.GetString(p.Protocol.Span)));
        }

        if (!string.Equals(hostname, _hostname, StringComparison.Ordinal) ||
            !string.Equals(alpnProtos, _alpnProtos, StringComparison.Ordinal))
        {
            RecreateConnection(hostname, alpnProtos);
        }

        _sslValidationCallback = options.RemoteCertificateValidationCallback;
        _revocationMode = NormalizeRevocationMode(options.CertificateRevocationCheckMode);

        if (options.EnabledSslProtocols is { } enabledProtocols &&
            enabledProtocols != SslProtocols.None &&
            (enabledProtocols & (SslProtocols.Tls12 | SslProtocols.Tls13)) == 0)
        {
            throw new NotSupportedException(
                $"NSS supports TLS 1.2 and TLS 1.3 only " +
                $"(EnabledSslProtocols: {enabledProtocols}).");
        }

        if (options.ClientCertificates is { Count: > 0 })
        {
            throw new NotSupportedException(
                "Client certificates (mTLS) are not supported by NssStream.");
        }

        if (options.LocalCertificateSelectionCallback is not null)
        {
            throw new NotSupportedException(
                "Local certificate selection is not supported by NssStream.");
        }
    }

    public string ProtocolVersion
    {
        get
        {
            ThrowIfDisposed();

            lock (_nativeSync)
            {
                return Marshal.PtrToStringUTF8(
                           Native.pms_ssl_get_protocol_version(
                               _connection))
                       ?? string.Empty;
            }
        }
    }

    public string CipherName
    {
        get
        {
            ThrowIfDisposed();

            lock (_nativeSync)
            {
                return Marshal.PtrToStringUTF8(
                           Native.pms_ssl_get_cipher_name(
                               _connection))
                       ?? string.Empty;
            }
        }
    }

    public string AlpnSelected
    {
        get
        {
            ThrowIfDisposed();

            lock (_nativeSync)
            {
                return Marshal.PtrToStringAnsi(
                           Native.pms_ssl_get_alpn_selected(
                               _connection))
                       ?? string.Empty;
            }
        }
    }

    public async ValueTask AuthenticateAsClientAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _readLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await _writeLock.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
                
            try
            {

                if (_authenticated)
                    return;

                _pumpTask ??= Task.Run(PumpLoopAsync);

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    int result;
                    string? nativeError = null;

                    lock (_nativeSync)
                    {
                        result = Native.pms_ssl_connect(_connection);

                        if (result == Native.PMS_SSL_ERROR)
                            nativeError = GetNativeError();
                    }

                    await FlushWriteBioAsync(
                            cancellationToken)
                        .ConfigureAwait(false);

                    switch (result)
                    {
                        case Native.PMS_SSL_OK:
                            ValidateServerCertificate(_hostname);
                            _authenticated = true;
                            return;

                        case Native.PMS_SSL_WANT_READ:
                            await ReadFromNetworkAsync(
                                    cancellationToken)
                                .ConfigureAwait(false);
                            break;

                        case Native.PMS_SSL_WANT_WRITE:
                            // Output has already been flushed.
                            break;

                        case Native.PMS_SSL_ZERO_RETURN:
                            throw new IOException(
                                "NSS handshake was closed " +
                                "by the peer.");

                        default:
                            throw CreateSslException(
                                "NSS handshake failed",
                                nativeError);
                    }
                }
            }
            finally
            {
                _writeLock.Release();
            }
        }
        finally
        {
            _readLock.Release();
        }
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
            return 0;

        await _readLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            EnsureAuthenticated();

            using MemoryHandle handle = buffer.Pin();

            IntPtr pointer = GetHandlePointer(handle);

            return await ReadCoreAsync(
                    pointer,
                    buffer.Length,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _readLock.Release();
        }
    }

    private async ValueTask<int> ReadCoreAsync(
        IntPtr buffer,
        int length,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int result;
            string? nativeError = null;

            lock (_nativeSync)
            {
                result = Native.pms_ssl_read(
                    _connection,
                    buffer,
                    length);

                if (result == Native.PMS_SSL_ERROR)
                    nativeError = GetNativeError();
            }

            // SSL_read can generate TLS output itself. Only wake the pump;
            // do NOT wait for it, otherwise a reader could get stuck behind
            // a blocked socket write and stop draining the socket.
            SignalPump();

            switch (result)
            {
                case > 0:
                    return result;

                case Native.PMS_SSL_ZERO_RETURN:
                    return 0;

                case Native.PMS_SSL_WANT_READ:
                    await ReadFromNetworkAsync(
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case Native.PMS_SSL_WANT_WRITE:
                    // Output is handled by the pump; retry.
                    break;

                default:
                    throw CreateSslException(
                        "NSS read failed",
                        nativeError);
            }
        }
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
            return;

        await _writeLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            EnsureAuthenticated();

            using MemoryHandle handle = buffer.Pin();

            IntPtr pointer = GetHandlePointer(handle);

            await WriteCoreAsync(
                    pointer,
                    buffer.Length,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask WriteCoreAsync(
        IntPtr buffer,
        int length,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IntPtr current = IntPtr.Add(buffer, offset);

            int result;
            string? nativeError = null;

            lock (_nativeSync)
            {
                result = Native.pms_ssl_write(
                    _connection,
                    current,
                    length - offset);

                if (result == Native.PMS_SSL_ERROR)
                    nativeError = GetNativeError();
            }

            await FlushWriteBioAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            switch (result)
            {
                case > 0:
                    offset += result;
                    break;

                case Native.PMS_SSL_WANT_READ:
                    // Would require reading the socket concurrently with the
                    // reader. Only happens with renegotiation, which is not
                    // supported (NSS clients reject it by default).
                    throw new IOException(
                        "TLS renegotiation is not supported.");

                case Native.PMS_SSL_WANT_WRITE:
                    // Output was flushed above.
                    break;

                case Native.PMS_SSL_ZERO_RETURN:
                    throw new IOException(
                        "NSS connection was closed " +
                        "by the peer.");

                default:
                    throw CreateSslException(
                        "NSS write failed",
                        nativeError);
            }
        }
    }

    private async ValueTask ReadFromNetworkAsync(
        CancellationToken cancellationToken)
    {
        byte[] buffer =
            ArrayPool<byte>.Shared.Rent(
                NetworkBufferSize);

        try
        {
            Memory<byte> memory =
                buffer.AsMemory(
                    0,
                    NetworkBufferSize);

            int read = await _innerStream.ReadAsync(
                    memory,
                    cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                throw new EndOfStreamException(
                    "Underlying stream was closed.");
            }

            using MemoryHandle handle =
                memory[..read].Pin();

            IntPtr pointer = GetHandlePointer(handle);
            int accepted;
            string? nativeError = null;

            lock (_nativeSync)
            {
                accepted =
                    Native.pms_ssl_feed_read(
                        _connection,
                        pointer,
                        read);

                if (accepted != read)
                    nativeError = GetNativeError();
            }

            if (accepted != read)
            {
                throw CreateSslException(
                    $"NSS accepted {accepted} " +
                    $"of {read} bytes",
                    nativeError);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Waits until everything currently in the write BIO has been written
    /// to the inner stream by the pump. Cancelling only stops the wait; the
    /// already-encrypted bytes are still sent (dropping them would corrupt
    /// the TLS record stream).
    /// </summary>
    private async ValueTask FlushWriteBioAsync(
        CancellationToken cancellationToken)
    {
        if (_pumpTask is null)
            return; // handshake has not started, nothing to flush

        var waiter = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        lock (_flushWaiters)
        {
            if (_pumpStopped)
                throw CreatePumpStoppedException();

            _flushWaiters.Add(waiter);
        }

        SignalPump();

        await waiter.Task
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private void SignalPump()
    {
        _flushSignal.Writer.TryWrite(true);
    }

    private async Task PumpLoopAsync()
    {
        CancellationToken token = _pumpCts.Token;
        var batch = new List<TaskCompletionSource>();
        Exception? failure = null;

        try
        {
            ChannelReader<bool> reader = _flushSignal.Reader;

            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                reader.TryRead(out _);

                // Waiters registered before the drain starts are covered by
                // it; later ones signal again and get the next round.
                lock (_flushWaiters)
                {
                    batch.AddRange(_flushWaiters);
                    _flushWaiters.Clear();
                }

                await DrainWriteBioAsync(token).ConfigureAwait(false);

                foreach (var waiter in batch)
                    waiter.TrySetResult();

                batch.Clear();
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // Disposed.
        }
        catch (Exception ex)
        {
            failure = ex;
        }
        finally
        {
            _pumpError = failure;

            lock (_flushWaiters)
            {
                _pumpStopped = true;
                batch.AddRange(_flushWaiters);
                _flushWaiters.Clear();
            }

            Exception error = CreatePumpStoppedException();

            foreach (var waiter in batch)
                waiter.TrySetException(error);
        }
    }

    private async ValueTask DrainWriteBioAsync(
        CancellationToken token)
    {
        IntPtr pointer =
            Marshal.UnsafeAddrOfPinnedArrayElement(_pumpBuffer, 0);

        while (true)
        {
            int taken;
            string? nativeError = null;

            lock (_nativeSync)
            {
                taken = Native.pms_ssl_take_write(
                    _connection,
                    pointer,
                    _pumpBuffer.Length);

                if (taken < 0)
                    nativeError = GetNativeError();
            }

            if (taken < 0)
            {
                throw CreateSslException(
                    "Failed to read NSS write BIO",
                    nativeError);
            }

            if (taken == 0)
                return; // BIO is empty

            await _innerStream.WriteAsync(
                    _pumpBuffer.AsMemory(0, taken),
                    token)
                .ConfigureAwait(false);
        }
    }

    private Exception CreatePumpStoppedException()
    {
        return _pumpError is { } error
            ? new IOException(
                "Failed to write TLS data to the underlying stream.",
                error)
            : new ObjectDisposedException(GetType().FullName);
    }

    private void StopPump()
    {
        try { _pumpCts.Cancel(); } catch { }

        _flushSignal.Writer.TryComplete();
    }

    private void EnsureAuthenticated()
    {
        if (!_authenticated)
        {
            throw new InvalidOperationException(
                "Call AuthenticateAsClientAsync() first.");
        }
    }

    private static IOException CreateSslException(
        string message,
        string? nativeError = null)
    {
        // The native error is thread-local: when an await sits between the
        // native call and this method, pass the text captured inside the lock.
        string error = nativeError ?? GetNativeError();

        return new IOException(
            string.IsNullOrWhiteSpace(error)
                ? message
                : $"{message}: {error}");
    }

    private static string GetNativeError()
    {
        IntPtr pointer =
            Native.pms_ssl_get_last_error();

        if (pointer == IntPtr.Zero)
            return "unknown native error";

        return Marshal.PtrToStringUTF8(pointer)
            ?? "unknown native error";
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(
            _disposed,
            this);
    }

    private static unsafe IntPtr GetHandlePointer(
        MemoryHandle handle)
    {
        return (IntPtr)handle.Pointer;
    }

    // ------------------------------------------------------------
    // Stream
    // ------------------------------------------------------------

    public override bool CanRead =>
        !_disposed;

    public override bool CanSeek =>
        false;

    public override bool CanWrite =>
        !_disposed;

    public override long Length =>
        throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        ThrowIfDisposed();

        FlushAsync(CancellationToken.None)
            .GetAwaiter()
            .GetResult();
    }

    public override Task FlushAsync(
        CancellationToken cancellationToken)
    {
        return FlushAsyncCore(
            cancellationToken);
    }

    private async Task FlushAsyncCore(
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await _writeLock.WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await FlushWriteBioAsync(
                    cancellationToken)
                .ConfigureAwait(false);

            await _innerStream.FlushAsync(
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override int Read(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        ValueTask<int> readTask = ReadAsync(
            buffer.AsMemory(offset, count),
            CancellationToken.None);

        if (readTask.IsCompleted)
        {
            return readTask
                .GetAwaiter()
                .GetResult();
        }
        else
        {
            return readTask
                .AsTask()
                .GetAwaiter()
                .GetResult();
        }
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        return ReadAsync(
                buffer.AsMemory(offset, count),
                cancellationToken)
            .AsTask();
    }

    public override void Write(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        ValueTask writeTask = WriteAsync(
            buffer.AsMemory(offset, count), 
            CancellationToken.None);

        if (writeTask.IsCompleted)
        {
            writeTask
                .GetAwaiter()
                .GetResult();
        }
        else
        {
            writeTask
                .AsTask()
                .GetAwaiter()
                .GetResult();
        }
    }

    public override Task WriteAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        ValidateBufferArguments(
            buffer,
            offset,
            count);

        return WriteAsync(
                buffer.AsMemory(offset, count),
                cancellationToken)
            .AsTask();
    }

    private static new void ValidateBufferArguments(
        byte[] buffer,
        int offset,
        int count)
    {
        if ((uint)offset > (uint)buffer.Length ||
            (uint)count > (uint)(buffer.Length - offset))
        {
            throw new ArgumentOutOfRangeException();
        }
    }

    public override long Seek(
        long offset,
        SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        _disposed = true;
        StopPump();

        if (disposing)
        {
            _readLock.Dispose();
            _writeLock.Dispose();

            if (!_leaveOpen)
                _innerStream.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;
        StopPump();

        _readLock.Dispose();
        _writeLock.Dispose();

        if (!_leaveOpen)
        {
            await _innerStream
                .DisposeAsync()
                .ConfigureAwait(false);
        }

        GC.SuppressFinalize(this);
    }

    // ------------------------------------------------------------
    // Native API
    // ------------------------------------------------------------

    private static partial class Native
    {
        internal const int PMS_SSL_OK = 1;
        internal const int PMS_SSL_ZERO_RETURN = 0;
        internal const int PMS_SSL_ERROR = -1;
        internal const int PMS_SSL_WANT_READ = -2;
        internal const int PMS_SSL_WANT_WRITE = -3;

        public sealed class SslHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SslHandle() : base(ownsHandle: true) { }
            protected override bool ReleaseHandle() { Native.pms_ssl_free(handle); return true; }
        }

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_create",
            StringMarshalling = StringMarshalling.Utf8)]
        internal static partial IntPtr pms_ssl_create(
            string hostname,
            string cipherList,
            int enableGrease,
            int enableEchGrease,
            string alpnProtos,
            string alpsProtos,
            string trustAnchors,
            string sigAlgs,
            int enableSignedCertTimestamps,
            int setOcspStatusType,
            int enableBrotli);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_connect")]
        internal static partial int pms_ssl_connect(
            SslHandle connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_feed_read")]
        internal static partial int pms_ssl_feed_read(
            SslHandle connection,
            IntPtr buffer,
            int length);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_take_write")]
        internal static partial int pms_ssl_take_write(
            SslHandle connection,
            IntPtr buffer,
            int length);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_pending_write")]
        internal static partial int pms_ssl_pending_write(
            SslHandle connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_read")]
        internal static partial int pms_ssl_read(
            SslHandle connection,
            IntPtr buffer,
            int length);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_write")]
        internal static partial int pms_ssl_write(
            SslHandle connection,
            IntPtr buffer,
            int length);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_get_protocol_version")]
        internal static partial IntPtr pms_ssl_get_protocol_version(
            SslHandle connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_get_cipher_name")]
        internal static partial IntPtr pms_ssl_get_cipher_name(
            SslHandle connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_get_alpn_selected")]
        internal static partial IntPtr pms_ssl_get_alpn_selected(
            SslHandle connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_get_last_error")]
        internal static partial IntPtr pms_ssl_get_last_error();

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_free")]
        internal static partial void pms_ssl_free(
            IntPtr connection);

        [LibraryImportAttribute(
            "proxymap_nss",
            EntryPoint = "pms_ssl_get_peer_certificate")]
        internal static partial int pms_ssl_get_peer_certificate(
            SslHandle connection,
            IntPtr buffer,
            int maxLength);
    }

    // ------------------------------------------------------------
    // Validate Server Certificate
    // ------------------------------------------------------------

    private void ValidateServerCertificate(string hostname)
    {
        int certLen;

        lock (_nativeSync)
        {
            certLen = Native.pms_ssl_get_peer_certificate(_connection, IntPtr.Zero, 0);

            if (certLen < 0)
                throw CreateSslException("Failed to get server certificate size");
        }

        if (certLen == 0)
        {
            throw new AuthenticationException("The server did not provide an SSL certificate.");
        }

        byte[] rentBuffer = ArrayPool<byte>.Shared.Rent(certLen);
        try
        {
            Memory<byte> memory = rentBuffer.AsMemory(0, certLen);
            using (MemoryHandle handle = memory.Pin())
            {
                IntPtr pointer = GetHandlePointer(handle);
                int readBytes;

                lock (_nativeSync)
                {
                    readBytes = Native.pms_ssl_get_peer_certificate(
                        _connection,
                        pointer,
                        certLen);

                    if (readBytes != certLen)
                        throw CreateSslException("Failed to read complete server certificate");
                }
            }

            using var certificate = new X509Certificate2(memory.Span);

            if (_sslValidationCallback is { } validate)
            {
                // SslStream-style callback: build the chain, compute the
                // policy errors and let the callback make the decision.
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = _revocationMode;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.ApplicationPolicy.Add(
                    new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")); // Server Auth

                chain.Build(certificate);

                var policyErrors = SslPolicyErrors.None;

                if (chain.ChainElements.Count == 0 ||
                    chain.ChainStatus.Any(s => s.Status != X509ChainStatusFlags.NoError))
                {
                    policyErrors |= SslPolicyErrors.RemoteCertificateChainErrors;
                }

                if (!certificate.MatchesHostname(hostname))
                {
                    policyErrors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                }

                if (!validate(this, certificate, chain, policyErrors))
                {
                    throw new AuthenticationException(
                        "The server certificate was rejected by " +
                        "RemoteCertificateValidationCallback.");
                }

                return;
            }

            if (RemoteCertificateValidationCallback is { } validateSimple)
            {
                if (!validateSimple(certificate))
                {
                    throw new AuthenticationException(
                        "The server certificate was rejected by RemoteCertificateValidationCallback.");
                }
                return;
            }

            using var defaultChain = new X509Chain();
            defaultChain.ChainPolicy.RevocationMode = _revocationMode;
            defaultChain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

            defaultChain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")); // Server Auth

            if (!defaultChain.Build(certificate))
            {
                var errors = string.Join(", ", defaultChain.ChainStatus.Select(s => s.StatusInformation.Trim()));
                throw new AuthenticationException($"Certificate chain validation failed: {errors}");
            }

            if (!certificate.MatchesHostname(hostname))
            {
                throw new AuthenticationException($"The hostname '{hostname}' does not match the server certificate.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentBuffer);
        }
    }
}