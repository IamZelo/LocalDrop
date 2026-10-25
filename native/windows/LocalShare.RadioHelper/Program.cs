using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Forms;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Enumeration;
using Windows.Devices.WiFiDirect;
using Windows.Storage.Streams;

internal static class Program
{
    private const ushort CompanyId = 0xFFFF; // Development/testing company identifier.
    private static readonly byte[] Magic = "LSS1"u8.ToArray();
    private static readonly byte[] CustomOui = [0xFA, 0xCE, 0x01];
    private static readonly object OutputLock = new();
    private static readonly ConcurrentDictionary<string, WiFiDirectDevice> Connections = new();
    private static BluetoothLEAdvertisementPublisher? _blePublisher;
    private static BluetoothLEAdvertisementWatcher? _bleWatcher;
    private static WiFiDirectAdvertisementPublisher? _wifiPublisher;
    private static WiFiDirectConnectionListener? _wifiListener;
    private static Control? _dispatcher;

    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            ApplicationConfiguration.Initialize();
            _dispatcher = new Control();
            _dispatcher.CreateControl();
            var token = ParseToken(args);
            var port = ParseArgument(args, "--port");
            var deviceId = ParseArgument(args, "--device-id");
            if (!ushort.TryParse(port, out var appPort) || appPort == 0) throw new ArgumentException("--port must be 1-65535");
            StartBluetooth(token);
            StartWiFiDirectListener(token, appPort, deviceId);
            Emit(new { @event = "ready", bluetooth = true, wifi_direct = true });
            _ = Task.Run(ReadCommandsAsync);
            Application.Run();
            Stop();
            return 0;
        }
        catch (Exception exception)
        {
            Emit(new { @event = "fatal", message = exception.Message, detail = exception.ToString() });
            return 1;
        }
    }

    private static async Task ReadCommandsAsync()
    {
        try
        {
            string? line;
            while ((line = await Console.In.ReadLineAsync()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                using var document = JsonDocument.Parse(line);
                var command = document.RootElement.GetProperty("command").GetString();
                switch (command)
                {
                    case "scan_wifi_direct":
                        await OnUiThread(ScanWiFiDirectAsync);
                        break;
                    case "connect_wifi_direct":
                        var id = document.RootElement.GetProperty("id").GetString()!;
                        await OnUiThread(() => ConnectWiFiDirectAsync(id));
                        break;
                    case "stop":
                        _dispatcher?.BeginInvoke(new Action(Application.ExitThread));
                        return;
                    default:
                        Emit(new { @event = "error", message = $"Unknown command: {command}" });
                        break;
                }
            }
            _dispatcher?.BeginInvoke(new Action(Application.ExitThread));
        }
        catch (Exception exception)
        {
            Emit(new { @event = "fatal", message = exception.Message, detail = exception.ToString() });
            _dispatcher?.BeginInvoke(new Action(Application.ExitThread));
        }
    }

    private static Task OnUiThread(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _dispatcher!.BeginInvoke(new Action(async () =>
        {
            try
            {
                await action();
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
            }
        }));
        return completion.Task;
    }

    private static byte[] ParseToken(string[] args)
    {
        var index = Array.IndexOf(args, "--token");
        if (index < 0 || index + 1 >= args.Length) throw new ArgumentException("--token HEX is required");
        var bytes = Convert.FromHexString(args[index + 1]);
        if (bytes.Length != 8) throw new ArgumentException("Discovery token must be exactly 8 bytes");
        return bytes;
    }

    private static string ParseArgument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0 || index + 1 >= args.Length) throw new ArgumentException($"{name} is required");
        return args[index + 1];
    }

    private static void StartBluetooth(byte[] token)
    {
        var payload = new byte[Magic.Length + token.Length + 1];
        Magic.CopyTo(payload, 0);
        token.CopyTo(payload, Magic.Length);
        payload[^1] = 1;

        using var writer = new DataWriter();
        writer.WriteBytes(payload);
        var advertisement = new BluetoothLEAdvertisement();
        advertisement.ManufacturerData.Add(new BluetoothLEManufacturerData(CompanyId, writer.DetachBuffer()));
        // IsAnonymous is supported only by some controllers/driver combinations and
        // makes Start() fail with E_INVALIDARG on common Windows laptops. The
        // application payload is still unlinkable because its token rotates each run.
        _blePublisher = new BluetoothLEAdvertisementPublisher(advertisement);
        _blePublisher.StatusChanged += (_, eventArgs) =>
            Emit(new { @event = "bluetooth_status", status = eventArgs.Status.ToString(), error = eventArgs.Error.ToString() });
        _blePublisher.Start();

        _bleWatcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
        _bleWatcher.Received += (_, eventArgs) =>
        {
            foreach (var section in eventArgs.Advertisement.ManufacturerData)
            {
                if (section.CompanyId != CompanyId) continue;
                var reader = DataReader.FromBuffer(section.Data);
                var bytes = new byte[checked((int)section.Data.Length)];
                reader.ReadBytes(bytes);
                if (bytes.Length != 13 || !bytes.AsSpan(0, 4).SequenceEqual(Magic)) continue;
                Emit(new
                {
                    @event = "ble_peer",
                    address = eventArgs.BluetoothAddress.ToString("X12"),
                    token = Convert.ToHexString(bytes.AsSpan(4, 8)),
                    version = bytes[12],
                    rssi = eventArgs.RawSignalStrengthInDBm
                });
            }
        };
        _bleWatcher.Stopped += (_, eventArgs) =>
            Emit(new { @event = "bluetooth_stopped", error = eventArgs.Error.ToString() });
        _bleWatcher.Start();
    }

    private static void StartWiFiDirectListener(byte[] token, ushort appPort, string deviceId)
    {
        _wifiPublisher = new WiFiDirectAdvertisementPublisher();
        _wifiPublisher.Advertisement.ListenStateDiscoverability = WiFiDirectAdvertisementListenStateDiscoverability.Intensive;
        _wifiPublisher.Advertisement.IsAutonomousGroupOwnerEnabled = true;
        var informationElement = new WiFiDirectInformationElement { OuiType = 1 };
        using (var ouiWriter = new DataWriter())
        {
            ouiWriter.WriteBytes(CustomOui);
            informationElement.Oui = ouiWriter.DetachBuffer();
        }
        using (var valueWriter = new DataWriter())
        {
            var identity = System.Text.Encoding.UTF8.GetBytes(deviceId);
            if (identity.Length > 64) throw new ArgumentException("Device identity is too long");
            var value = Magic.Concat(token)
                .Concat(new[] { (byte)(appPort >> 8), (byte)appPort, (byte)identity.Length })
                .Concat(identity).ToArray();
            valueWriter.WriteBytes(value);
            informationElement.Value = valueWriter.DetachBuffer();
        }
        _wifiPublisher.Advertisement.InformationElements.Add(informationElement);
        _wifiPublisher.StatusChanged += (_, eventArgs) =>
            Emit(new { @event = "wifi_direct_status", status = eventArgs.Status.ToString(), error = eventArgs.Error.ToString() });

        _wifiListener = new WiFiDirectConnectionListener();
        _wifiListener.ConnectionRequested += async (_, eventArgs) =>
        {
            try
            {
                var request = eventArgs.GetConnectionRequest();
                await OnUiThread(async () =>
                {
                    using (request)
                    {
                        var parameters = await PairForWiFiDirectAsync(request.DeviceInformation);
                        var device = await WiFiDirectDevice.FromIdAsync(request.DeviceInformation.Id, parameters);
                        TrackConnection(device, request.DeviceInformation.Name);
                    }
                });
            }
            catch (Exception exception)
            {
                Emit(new { @event = "wifi_direct_error", message = exception.Message });
            }
        };
        _wifiPublisher.Start();
    }

    private static async Task ScanWiFiDirectAsync()
    {
        try
        {
            var selector = WiFiDirectDevice.GetDeviceSelector(WiFiDirectDeviceSelectorType.AssociationEndpoint);
            string[] additionalProperties = ["System.Devices.WiFiDirect.InformationElements"];
            var devices = await DeviceInformation.FindAllAsync(selector, additionalProperties);
            var found = 0;
            foreach (var device in devices)
            {
                string? token = null;
                foreach (var element in WiFiDirectInformationElement.CreateFromDeviceInformation(device))
                {
                    if (element.OuiType != 1) continue;
                    var oui = ReadBuffer(element.Oui);
                    var value = ReadBuffer(element.Value);
                    if (!oui.SequenceEqual(CustomOui) || value.Length < 15 || !value.AsSpan(0, 4).SequenceEqual(Magic)) continue;
                    var identityLength = value[14];
                    if (value.Length != 15 + identityLength) continue;
                    token = Convert.ToHexString(value.AsSpan(4, 8));
                    var port = (value[12] << 8) | value[13];
                    var deviceId = System.Text.Encoding.UTF8.GetString(value, 15, identityLength);
                    Emit(new { @event = "wifi_direct_peer", id = device.Id, name = device.Name, paired = device.Pairing.IsPaired, token, port, device_id = deviceId });
                    break;
                }
                if (token is not null)
                {
                    found++;
                }
            }
            Emit(new { @event = "wifi_direct_scan_complete", count = found });
        }
        catch (Exception exception)
        {
            Emit(new { @event = "wifi_direct_error", message = exception.Message });
        }
    }

    private static byte[] ReadBuffer(IBuffer buffer)
    {
        var reader = DataReader.FromBuffer(buffer);
        var bytes = new byte[checked((int)buffer.Length)];
        reader.ReadBytes(bytes);
        return bytes;
    }

    private static async Task ConnectWiFiDirectAsync(string id)
    {
        try
        {
            var information = await DeviceInformation.CreateFromIdAsync(id);
            var parameters = await PairForWiFiDirectAsync(information);
            var device = await WiFiDirectDevice.FromIdAsync(id, parameters);
            TrackConnection(device, information.Name);
        }
        catch (Exception exception)
        {
            Emit(new { @event = "wifi_direct_error", message = exception.Message });
        }
    }

    private static async Task<WiFiDirectConnectionParameters> PairForWiFiDirectAsync(DeviceInformation information)
    {
        var parameters = new WiFiDirectConnectionParameters();
        parameters.PreferenceOrderedConfigurationMethods.Add(WiFiDirectConfigurationMethod.PushButton);
        if (information.Pairing.IsPaired || !information.Pairing.CanPair) return parameters;

        var kinds = WiFiDirectConnectionParameters.GetDevicePairingKinds(WiFiDirectConfigurationMethod.PushButton);
        var custom = information.Pairing.Custom;
        void OnPairingRequested(DeviceInformationCustomPairing _, DevicePairingRequestedEventArgs args)
        {
            Emit(new { @event = "wifi_direct_pairing_ceremony", kind = args.PairingKind.ToString() });
            if (args.PairingKind == DevicePairingKinds.ConfirmOnly) args.Accept();
        }

        custom.PairingRequested += OnPairingRequested;
        try
        {
            var result = await custom.PairAsync(kinds, DevicePairingProtectionLevel.Default, parameters);
            if (result.Status is not DevicePairingResultStatus.Paired and not DevicePairingResultStatus.AlreadyPaired)
            {
                // Windows can report Failed even after creating the P2P association.
                // Continue to FromIdAsync, which is the authoritative link attempt.
                Emit(new { @event = "wifi_direct_pairing_warning", status = result.Status.ToString() });
            }
        }
        finally
        {
            custom.PairingRequested -= OnPairingRequested;
        }
        return parameters;
    }

    private static void TrackConnection(WiFiDirectDevice device, string name)
    {
        var key = device.DeviceId;
        Connections[key] = device;
        device.ConnectionStatusChanged += (_, _) =>
            Emit(new { @event = "wifi_direct_connection_status", id = key, status = device.ConnectionStatus.ToString() });
        var endpoints = device.GetConnectionEndpointPairs();
        foreach (var endpoint in endpoints)
        {
            Emit(new
            {
                @event = "wifi_direct_connected",
                id = key,
                name,
                local_address = endpoint.LocalHostName?.CanonicalName,
                remote_address = endpoint.RemoteHostName?.CanonicalName
            });
        }
    }

    private static void Stop()
    {
        _bleWatcher?.Stop();
        _blePublisher?.Stop();
        _wifiPublisher?.Stop();
        foreach (var device in Connections.Values) device.Dispose();
        Connections.Clear();
    }

    private static void Emit(object value)
    {
        lock (OutputLock)
        {
            Console.Out.WriteLine(JsonSerializer.Serialize(value));
            Console.Out.Flush();
        }
    }
}
