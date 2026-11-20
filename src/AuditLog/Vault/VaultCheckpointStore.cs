using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuditLog.Anchoring;

namespace AuditLog.Vault;

/// <summary>
/// Talks to Vault over its HTTP API: KV v2 for checkpoints and heads, Transit for signatures.
/// <para>
/// No token is needed when Vault Agent sits in front of Vault (agent proxy mode): the agent injects
/// its auto-auth token. A static token is used only when the API talks to Vault directly.
/// </para>
/// </summary>
public sealed class VaultCheckpointStore(VaultOptions options, HttpClient httpClient) : ICheckpointStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task WaitUntilReadyAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(options.StartupTimeoutSeconds);
        Exception? last = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await ReadPublicKeyAsync(null, cancellationToken);
                return;
            }
            catch (AuditLogUnavailableException ex)
            {
                last = ex;
                await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
            }
        }

        throw new AuditLogUnavailableException(
            $"Vault at {options.Address} is not ready after {options.StartupTimeoutSeconds}s. " +
            $"Expected the '{options.TransitKey}' signing key in the '{options.TransitMountPoint}' mount. {last?.Message}",
            last);
    }

    public async Task<SignatureResult> SignAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var body = new
        {
            input = Convert.ToBase64String(payload),
            hash_algorithm = "sha2-256",
            prehashed = false
        };

        var response = await SendAsync(
            HttpMethod.Post,
            $"transit/sign/{options.TransitKey}",
            body,
            cancellationToken);

        var data = response.GetProperty("data");
        var signature = data.GetProperty("signature").GetString()
            ?? throw new AuditLogUnavailableException("Vault Transit returned no signature.");
        var keyVersion = data.TryGetProperty("key_version", out var version) ? version.GetInt32() : 0;

        return new SignatureResult(DecodeSignature(signature), keyVersion);
    }

    public async Task<PublicSigningKey> ReadPublicKeyAsync(int? keyVersion, CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            HttpMethod.Get,
            $"transit/keys/{options.TransitKey}",
            null,
            cancellationToken);

        var data = response.GetProperty("data");
        var name = data.GetProperty("name").GetString() ?? options.TransitKey;
        var latest = data.GetProperty("latest_version").GetInt32();
        var version = keyVersion ?? latest;
        var keys = data.GetProperty("keys");

        if (!keys.TryGetProperty(version.ToString(CultureInfo.InvariantCulture), out var pemElement))
        {
            throw new AuditLogUnavailableException(
                $"Vault Transit key '{name}' has no public key for version {version}.");
        }

        // Vault < 1.20 returns the PEM directly; newer versions return an object with public_key.
        var pem = pemElement.ValueKind == JsonValueKind.String
            ? pemElement.GetString()
            : pemElement.TryGetProperty("public_key", out var publicKey) ? publicKey.GetString() : null;

        if (string.IsNullOrWhiteSpace(pem))
            throw new AuditLogUnavailableException($"Vault Transit key '{name}' version {version} has no public key.");

        return new PublicSigningKey(name, version, pem);
    }

    public async Task PutCheckpointAsync(string ledger, AnchoredCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        var path = CheckpointPath(ledger, checkpoint.Checkpoint.CreatedAt, checkpoint.Checkpoint.Seq);
        var body = new
        {
            data = new Dictionary<string, string>
            {
                ["payload"] = Convert.ToBase64String(checkpoint.Payload),
                ["signature"] = Convert.ToBase64String(checkpoint.Signature),
                ["key_version"] = checkpoint.KeyVersion.ToString(CultureInfo.InvariantCulture),
                ["checkpoint_hash"] = Hex.Encode(checkpoint.PayloadHash),
                ["tree_size"] = checkpoint.Checkpoint.TreeSize.ToString(CultureInfo.InvariantCulture),
                ["root"] = Hex.Encode(checkpoint.Checkpoint.Root)
            }
        };

        await SendAsync(HttpMethod.Post, path, body, cancellationToken);
    }

    public async Task<AnchoredCheckpoint?> ReadCheckpointAsync(
        string ledger, long seq, DateTimeOffset createdAt, CancellationToken cancellationToken)
    {
        var path = CheckpointPath(ledger, createdAt, seq);
        var response = await TrySendAsync(HttpMethod.Get, path, cancellationToken);
        if (response is null)
            return null;

        var data = response.Value.GetProperty("data").GetProperty("data");
        var payload = Convert.FromBase64String(data.GetProperty("payload").GetString()!);
        var signature = Convert.FromBase64String(data.GetProperty("signature").GetString()!);
        var keyVersion = int.Parse(data.GetProperty("key_version").GetString()!, CultureInfo.InvariantCulture);

        return new AnchoredCheckpoint(
            CheckpointCodec.Decode(payload),
            payload,
            signature,
            keyVersion,
            CheckpointCodec.HashPayload(payload));
    }

    public async Task PutHeadsAsync(LedgerHeads heads, CancellationToken cancellationToken)
    {
        var body = new
        {
            data = new Dictionary<string, string>
            {
                ["ledger"] = heads.Ledger,
                ["seq"] = heads.Seq.ToString(CultureInfo.InvariantCulture),
                ["tree_size"] = heads.TreeSize.ToString(CultureInfo.InvariantCulture),
                ["root"] = Hex.Encode(heads.Root),
                ["checkpoint_hash"] = Hex.Encode(heads.CheckpointHash),
                ["updated_at"] = heads.UpdatedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
            }
        };

        await SendAsync(HttpMethod.Post, HeadsPath(heads.Ledger), body, cancellationToken);
    }

    public async Task<LedgerHeads?> ReadHeadsAsync(string ledger, CancellationToken cancellationToken)
    {
        var response = await TrySendAsync(HttpMethod.Get, HeadsPath(ledger), cancellationToken);
        if (response is null)
            return null;

        var data = response.Value.GetProperty("data").GetProperty("data");
        return new LedgerHeads(
            data.GetProperty("ledger").GetString() ?? ledger,
            long.Parse(data.GetProperty("seq").GetString()!, CultureInfo.InvariantCulture),
            long.Parse(data.GetProperty("tree_size").GetString()!, CultureInfo.InvariantCulture),
            Hex.Decode(data.GetProperty("root").GetString()!),
            Hex.Decode(data.GetProperty("checkpoint_hash").GetString()!),
            DateTimeOffset.Parse(
                data.GetProperty("updated_at").GetString()!,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));
    }

    private string CheckpointPath(string ledger, DateTimeOffset createdAt, long seq) =>
        $"{options.KvMountPoint}/data/{options.BasePath}/checkpoints/{ledger}/{createdAt.UtcDateTime:yyyy}/{seq:D10}";

    private string HeadsPath(string ledger) =>
        $"{options.KvMountPoint}/data/{options.BasePath}/heads/{ledger}";

    private static byte[] DecodeSignature(string signature)
    {
        // Transit returns "vault:v<version>:<base64 DER>".
        var parts = signature.Split(':');
        if (parts.Length != 3 || parts[0] != "vault")
            throw new AuditLogUnavailableException($"Unexpected Vault Transit signature format: '{signature[..Math.Min(signature.Length, 16)]}...'.");

        return Convert.FromBase64String(parts[2]);
    }

    private async Task<JsonElement> SendAsync(
        HttpMethod method, string path, object? body, CancellationToken cancellationToken)
    {
        var response = await SendCoreAsync(method, path, body, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            response.Dispose();
            throw new AuditLogUnavailableException($"Vault returned 404 for {method} {path}.");
        }

        using (response)
        {
            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new AuditLogUnavailableException(
                    $"Vault {method} {path} failed with {(int)response.StatusCode}: {Truncate(text)}");
            }

            if (string.IsNullOrWhiteSpace(text))
                return default;

            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }
    }

    private async Task<JsonElement?> TrySendAsync(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        var response = await SendCoreAsync(method, path, null, cancellationToken);
        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NotFound)
                return null;

            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new AuditLogUnavailableException(
                    $"Vault {method} {path} failed with {(int)response.StatusCode}: {Truncate(text)}");
            }

            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }
    }

    private async Task<HttpResponseMessage> SendCoreAsync(
        HttpMethod method, string path, object? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, $"v1/{path}");
        if (!string.IsNullOrEmpty(options.Token))
            request.Headers.TryAddWithoutValidation("X-Vault-Token", options.Token);
        if (body is not null)
            request.Content = JsonContent.Create(body, options: JsonOptions);

        try
        {
            return await httpClient.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException ex)
        {
            throw new AuditLogUnavailableException($"Vault is unreachable at {options.Address}.", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuditLogUnavailableException($"Vault at {options.Address} timed out.", ex);
        }
    }

    private static string Truncate(string text) => text.Length <= 500 ? text : text[..500] + "…";
}
