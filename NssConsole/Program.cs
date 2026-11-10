using System.IO.Enumeration;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

using NssSsl;

const string host = "tls.peet.ws";
//const string host = "kittens.sh";
//const string host = "google.com";
//const string host = "expired.badssl.com";
//const string host = "untrusted-root.badssl.com";
//const string host = "revoked.badssl.com";
const string document = "/api/tls";
const int port = 443;

using var client = new TcpClient();

Console.WriteLine($"Connecting to {host}:{port}...");

await client.ConnectAsync(host, port);

Console.WriteLine("TCP connected.");

await using NetworkStream networkStream = client.GetStream();

using var sslStream = new NssStream(
    networkStream,
    host,
    cipherList: Environment.GetEnvironmentVariable("NSS_CIPHERS") ?? NssSsl.NssStream.ChromeCipherSuitePreset,
    enableGrease: Environment.GetEnvironmentVariable("NSS_GREASE") is null
        ? NssSsl.NssStream.ChromeEnableGreasePreset
        : (Environment.GetEnvironmentVariable("NSS_GREASE") == "1" ? 1 : 0),
    sigAlgs: Environment.GetEnvironmentVariable("NSS_SIGALGS") ?? NssSsl.NssStream.ChromeSignatureAlgorithmsPreset);

Console.WriteLine("Starting NSS handshake...");

await sslStream.AuthenticateAsClientAsync();

Console.WriteLine($"TLS version:   {sslStream.ProtocolVersion}");
Console.WriteLine($"Cipher:        {sslStream.CipherName}");

string alpn = sslStream.AlpnSelected;

Console.WriteLine($"Alpn selected: {alpn}");

bool http2 = string.Equals("h2", alpn);

Console.WriteLine();

if (http2)
{
    Console.WriteLine("Sending HTTP/2 request...");

    // 1. Send the mandatory 24-byte HTTP/2 Connection Preface sequence
    byte[] preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    await sslStream.WriteAsync(preface);

    // 2. Send an initial empty SETTINGS frame (Length: 0, Type: 0x04, Flags: 0x00, Stream ID: 0)
    byte[] settingsFrame = new byte[] { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    await sslStream.WriteAsync(settingsFrame);

    // 3. Assemble the HPACK binary buffer block
    using var ms = new MemoryStream();

    var hpack = new HpackEncoder(ms);

    // Write standard pseudo-headers using static HPACK table index shortcuts (RFC 7541)
    hpack.WriteIndexed(2); // :method: GET
    hpack.WriteIndexed(7); // :scheme: https

    // Write dynamic string fields using custom literal representation rules
    hpack.WriteLiteralWithoutIndexing(1, host);     // :authority (Index 1)
    hpack.WriteLiteralWithoutIndexing(4, document); // :path (Index 4)

    hpack.WriteLiteralWithoutIndexing(
        "user-agent",
        "NssConsole/1.0");

    hpack.WriteLiteralWithoutIndexing(
        "accept",
        "*.*");

    byte[] fullPayload = ms.ToArray();

    int payloadLength = fullPayload.Length;

    // 4. Construct the standard 9-byte HTTP/2 HEADERS frame envelope header
    // Flags set to: END_STREAM (0x01) | END_HEADERS (0x04) = 0x05. Outgoing Stream ID: 1
    byte[] headersFrameHeader = new byte[9];
    headersFrameHeader[0] = (byte)((payloadLength >> 16) & 0xFF); // Length High
    headersFrameHeader[1] = (byte)((payloadLength >> 8) & 0xFF);  // Length Mid
    headersFrameHeader[2] = (byte)(payloadLength & 0xFF);         // Length Low
    headersFrameHeader[3] = 0x01;                                 // Frame Type: HEADERS (0x01)
    headersFrameHeader[4] = 0x05;                                 // Flags bitmask
    headersFrameHeader[5] = 0x00;                                 // Stream ID Reserved
    headersFrameHeader[6] = 0x00;                                 
    headersFrameHeader[7] = 0x00;                                 
    headersFrameHeader[8] = 0x01;                                 // Stream ID = 1

    // Dispatch the frame package directly across the wire
    await sslStream.WriteAsync(headersFrameHeader);
    await sslStream.WriteAsync(fullPayload);
}
else
{
    Console.WriteLine("Sending HTTP/1.1 request...");


    const string request =
        $"GET {document} HTTP/1.1\r\n" +
        $"Host: {host}\r\n" +
        "User-Agent: NssConsole/1.0\r\n" +
        "Accept: *.*\r\n" +
        "Connection: close\r\n" +
        "\r\n";

    var requestBytes = Encoding.ASCII.GetBytes(request);

    await sslStream.WriteAsync(
        requestBytes.AsMemory(
            0, requestBytes.Length));
}

const string output_dir = "./output/";
if (!Directory.Exists(output_dir))
{
    Directory.CreateDirectory(output_dir);
}

const string filename = $"{output_dir}{host}.txt";

using var file = File.Create(filename);

if (http2)
{
    Console.WriteLine("\r\n--- Receiving HTTP/2 Response Frames ---");

    // In HTTP/2, incoming data arrives strictly as framed envelopes: 9-byte header + payload payloadLength
    byte[] frameHeader = new byte[9];

    try
    {
        while (true)
        {
            // 1. Read exactly 9 bytes to capture the upcoming frame envelope header
            int headerBytesRead = 0;
            while (headerBytesRead < 9)
            {
                int read = await sslStream.ReadAsync(frameHeader.AsMemory(headerBytesRead, 9 - headerBytesRead));
                if (read == 0) break;
                headerBytesRead += read;
            }

            // Exit structural parsing cleanly if the streaming wire connection has dropped closed
            if (headerBytesRead == 0) break; 
            if (headerBytesRead < 9) throw new Exception("Incomplete HTTP/2 frame header received.");

            // 2. Parse out the structured metadata values from the envelope header (RFC 7540)
            int payloadLength = (frameHeader[0] << 16) | (frameHeader[1] << 8) | frameHeader[2];
            byte frameType = frameHeader[3];
            byte flags = frameHeader[4];
            int streamId = ((frameHeader[5] & 0x7F) << 24) | (frameHeader[6] << 16) | (frameHeader[7] << 8) | frameHeader[8];

            // 3. Read the downstream payload allocation slice matching the explicit payload length descriptor
            byte[] payload = new byte[payloadLength];
            int payloadBytesRead = 0;
            while (payloadBytesRead < payloadLength)
            {
                int read = await sslStream.ReadAsync(payload.AsMemory(payloadBytesRead, payloadLength - payloadBytesRead));
                if (read == 0) break;
                payloadBytesRead += read;
            }

            // 4. Process individual payload data blocks depending on incoming Frame Type
            if (frameType == 0x00) // DATA Frame (Payload Body Fragment)
            {
                if (payloadLength > 0)
                {
                    file.Write(payload, 0, payloadLength);
                    Console.Write(Encoding.UTF8.GetString(payload));
                }

                // If the END_STREAM flag bitmask (0x01) is active, the remote host has finished transmission
                if ((flags & 0x01) != 0)
                {
                    Console.WriteLine("\n[Stream Ended by Server (DATA)]");
                    break;
                }
            }
            else if (frameType == 0x01) // HEADERS Frame (Contains response HTTP statuses and metadata)
            {
                Console.WriteLine($"\n[Received HEADERS frame for Stream {streamId}, Length: {payloadLength} bytes]");
                
                // Fast-lookup heuristic workaround to capture the return HTTP status without a full HPACK decoder:
                // Pre-mapped standard status responses sit as byte indices inside the static HPACK table (0x80 mask):
                // 0x88 -> :status: 200
                // 0x89 -> :status: 204
                // 0x8A -> :status: 206
                // 0x8B -> :status: 304
                // 0x8C -> :status: 400
                // 0x8D -> :status: 404  <-- Resource Not Found indicator
                // 0x8E -> :status: 500
                
                int foundStatus = 0;
                for (int i = 0; i < payload.Length; i++)
                {
                    if (payload[i] >= 0x88 && payload[i] <= 0x8E)
                    {
                        foundStatus = payload[i] switch
                        {
                            0x88 => 200,
                            0x89 => 204,
                            0x8A => 206,
                            0x8B => 304,
                            0x8C => 400,
                            0x8D => 404,
                            0x8E => 500,
                            _ => 0
                        };
                        break;
                    }
                }

                if (foundStatus != 0)
                {
                    Console.WriteLine($"[HTTP Status Inferred]: {foundStatus}");
                    if (foundStatus == 404)
                    {
                        Console.WriteLine("[Warning]: Resource not found (404 Not Found). The response payload might be empty or contain an error page layout.");
                    }
                }
                else
                {
                    Console.WriteLine("[HTTP Status]: Unable to determine (server used a dynamic or rare status index code)");
                }

                // If a HEADERS frame package returns with the END_STREAM flag active (e.g., 204 No Content / 304 Not Modified),
                // no trailing DATA segments will arrive. Terminate loop processing immediately.
                if ((flags & 0x01) != 0)
                {
                    Console.WriteLine("[Stream Ended by Server (HEADERS)]");
                    break;
                }
            }
            else if (frameType == 0x03) // RST_STREAM Frame (Server aborted processing for this specific stream context)
            {
                long errorCode = 0;
                if (payloadLength >= 4)
                {
                    errorCode = ((long)payload[0] << 24) | ((long)payload[1] << 16) | ((long)payload[2] << 8) | payload[3];
                }
                Console.WriteLine($"\n[RST_STREAM] Server aborted stream processing for ID {streamId}. Error Code: 0x{errorCode:X} ({GetHttp2ErrorName(errorCode)})");
                break; 
            }
            else if (frameType == 0x07) // GOAWAY frame (server is closing the entire connection)
            {
                long errorCode = 0;
                if (payloadLength >= 8)
                {
                    errorCode = ((long)payload[4] << 24) | ((long)payload[5] << 16) | ((long)payload[6] << 8) | payload[7];
                }
                Console.WriteLine($"\n[GOAWAY] Server is closing the connection. Error code: 0x{errorCode:X} ({GetHttp2ErrorName(errorCode)})");
                break;
            }
            else if (frameType == 0x04) // SETTINGS frame
            {
                // On a SETTINGS frame from the server (if it is not an ACK), the client is obligated to respond with its own SETTINGS-ACK frame.
                // Google usually tolerates a missing ACK for simple console requests, but per RFC this is required:
                bool isAck = (flags & 0x01) != 0;
                if (!isAck)
                {
                    // Send SETTINGS with the ACK flag (0x01), length 0, Stream ID 0
                    byte[] settingsAck = new byte[] { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
                    await sslStream.WriteAsync(settingsAck);
                    Console.WriteLine("[SETTINGS] Received server settings. Sent SETTINGS ACK.");
                }
            }
            else if (frameType == 0x08) // WINDOW_UPDATE frame
            {
                // Service frame for managing the data transmission window size. The log can safely be skipped.
                // Console.WriteLine($"[WINDOW_UPDATE] Window changed by {payloadLength} bytes.");
            } 
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"\r\nError while reading HTTP/2 stream: {ex.Message}");
    }   
}
else 
{
    const int bufferSize = 16 * 1024;

    var buffer = new byte[bufferSize];
    while (true)
    {
        int read = await sslStream.ReadAsync(buffer.AsMemory(0, bufferSize));
        if (read == 0)
            break;

        file.Write(buffer, 0, read);

        Console.Write(Encoding.UTF8.GetString(buffer, 0, read));
    }
}

Console.WriteLine($"\r\n\r\nSaved response to {filename}");

static string GetHttp2ErrorName(long errorCode) => errorCode switch
{
    0x00 => "NO_ERROR",
    0x01 => "PROTOCOL_ERROR (protocol error / invalid headers)",
    0x02 => "INTERNAL_ERROR",
    0x03 => "FLOW_CONTROL_ERROR",
    0x05 => "STREAM_CLOSED",
    0x06 => "FRAME_SIZE_ERROR",
    0x07 => "REFUSED_STREAM",
    0x0d => "HTTP_1_1_REQUIRED",
    _ => "UNKNOWN_ERROR"
};