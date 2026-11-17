using LibUsbDotNet;
using LibUsbDotNet.LibUsb;
using LibUsbDotNet.Main;
using Microsoft.Win32;
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FingerprintRawView
{
    class Program
    {
        private static IUsbDevice _device = null;
        private static readonly UsbDeviceFinder MyUsbFinder = new() { Vid = 0x2541, Pid = 0x0236 };

        private static readonly object _bitmapLock = new();
        private static PictureBox _pb;
        private static Bitmap _bmp;
        private static Form _mainForm;

        private static readonly CancellationTokenSource _cts = new();

        private const int Width = 68;
        private const int Height = 118;
        private const int Zoom = 2;

        [STAThread]
        static async Task Main()
        {
            Console.Title = "ChipSailing CS9711 - Fingerprint Raw View | By LDj3SNuD";

            if (!IsWinUsbDriverInstalled())
            {
                Console.WriteLine("Driver corretto non rilevato o non configurato su WinUSB;");
                Console.WriteLine("Usare Zadig (https://zadig.akeo.ie/) [https://github.com/pbatard/libwdi/releases/download/v1.5.1/zadig-2.9.exe].");

                Console.ReadLine();

                return;
            }

            Console.WriteLine("Driver WinUSB configurato e pronto all'uso.");

            /**/

            InitializeGraphics();

            Thread uiThread = new(() => Application.Run(_mainForm));
            uiThread.SetApartmentState(ApartmentState.STA);
            uiThread.IsBackground = true;
            uiThread.Start();

            Thread quitThread = new(() =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        _cts.Cancel();
                        break;
                    }
                    Thread.Sleep(100);
                }
            }) { IsBackground = true };
            quitThread.Start();

            try
            {
                await Task.Run(() => RunUsbLoop(_cts.Token), _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Operazione annullata dall'utente.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Errore critico: {ex.Message}");
            }
            finally
            {
                Cleanup();

                Console.ReadLine();
            }
        }

        private static bool IsWinUsbDriverInstalled()
        {
            const string registryPath = @"SYSTEM\CurrentControlSet\Enum\USB\VID_2541&PID_0236";

            try
            {
                using (RegistryKey baseKey = Registry.LocalMachine.OpenSubKey(registryPath))
                {
                    if (baseKey == null) return false;

                    string[] subKeyNames = baseKey.GetSubKeyNames();
                    foreach (string subKeyName in subKeyNames)
                    {
                        using (RegistryKey instanceKey = baseKey.OpenSubKey(subKeyName))
                        {
                            if (instanceKey == null) continue;

                            object serviceValue = instanceKey.GetValue("Service");
                            if (serviceValue != null)
                            {
                                if (string.Equals(serviceValue.ToString(), "WinUSB", StringComparison.OrdinalIgnoreCase)) // !WUDFRd
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Errore durante la lettura del registro di sistema: {ex.Message}");
            }

            return false;
        }

        private static void InitializeGraphics()
        {
            _pb = new PictureBox
            {
                Dock = DockStyle.Fill,
                SizeMode = PictureBoxSizeMode.Zoom,
                Width = Width * Zoom,
                Height = Height * Zoom
            };

            _bmp = new Bitmap(Width, Height, PixelFormat.Format8bppIndexed);
            InitializeGrayPalette();
            _pb.Image = _bmp;

            var btn = new Button { Text = "Salva Impronta", Dock = DockStyle.Bottom };
            btn.Click += CaptureButton_Click;

            _mainForm = new Form
            {
                Text = "Fingerprint Raw View",
                StartPosition = FormStartPosition.CenterScreen,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                MaximizeBox = false
            };
            _mainForm.Controls.Add(_pb);
            _mainForm.Controls.Add(btn);

            _mainForm.FormClosing += (_, _) => _cts.Cancel();
        }

        private static void InitializeGrayPalette()
        {
            ColorPalette palette = _bmp.Palette;
            for (int i = 0; i < 256; i++)
            {
                palette.Entries[i] = Color.FromArgb(i, i, i);
            }
            _bmp.Palette = palette;
        }

        private static void CaptureButton_Click(object sender, EventArgs e)
        {
            string directory = Path.Combine(AppContext.BaseDirectory, "Captures");
            if (!Directory.Exists(directory)) Directory.CreateDirectory(directory);

            string path = Path.Combine(directory, $"ID_{DateTime.Now:yyyyMMdd_HHmmss_fff}.bmp");

            lock (_bitmapLock)
            {
                _bmp.Save(path, ImageFormat.Bmp);
            }
            Console.WriteLine($"Immagine salvata in: {path}");
        }

        private static void RunUsbLoop(CancellationToken token)
        {
            using UsbContext context = new();
            _device = context.Find(MyUsbFinder) as UsbDevice ?? throw new Exception("Dispositivo USB non trovato.");

            _device.Open();

            if (_device is IUsbDevice wholeDevice)
            {
                wholeDevice.SetConfiguration(1);
                wholeDevice.ClaimInterface(0);
            }

            var writer = _device.OpenEndpointWriter(WriteEndpointID.Ep01);
            var reader = _device.OpenEndpointReader(ReadEndpointID.Ep01);

            byte[] initBytes = [0xEA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEA];
            byte[] handshake = [0xEA, 0x01, 0x62, 0xA0, 0x00, 0x00, 0xC3, 0xEA];
            byte[] initScan = [0xEA, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0xEA];
            byte[] postScan = [0xEA, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0xEA];

            byte[] initResponse = new byte[8];

            reader.ReadFlush();
            writer.Write(initBytes, 250, out _);
            reader.Read(initResponse, 250, out _);

            if (!initResponse.AsSpan().SequenceEqual(handshake))
                throw new Exception("Inizializzazione fallita (Handshake USB non valido).");

            Console.WriteLine("Sensore inizializzato. Pronto per l'acquisizione.");
            Thread.Sleep(250);

            byte[] totalBuffer = new byte[8024];

            while (!token.IsCancellationRequested)
            {
                writer.Write(initScan, 1000, out _);

                Error ecRead1 = reader.Read(totalBuffer, 0, 8000, 2500, out int bytesRead1);
                Error ecRead2 = reader.Read(totalBuffer, 8000, 24, 250, out int bytesRead2);

                if (ecRead1 == Error.Success && ecRead2 == Error.Success && (bytesRead1 + bytesRead2) == totalBuffer.Length)
                {
                    ProcessBufferForBmp(totalBuffer);

                    if (_pb.IsHandleCreated && !_pb.IsDisposed)
                    {
                        _pb.BeginInvoke(new Action(() => _pb.Refresh()));
                    }
                }
                else
                {
                    reader.ReadFlush();
                    if (ecRead1 != Error.Timeout)
                    {
                        Console.WriteLine($"Errore di lettura hardware: {ecRead1}");
                    }
                }

                writer.Write(postScan, 250, out _);

                if (token.WaitHandle.WaitOne(250)) break;
            }
        }

        private static void ProcessBufferForBmp(byte[] data)
        {
            const int sensorWidth = 34;

            lock (_bitmapLock)
            {
                BitmapData bmpData = _bmp.LockBits(
                    new Rectangle(0, 0, _bmp.Width, _bmp.Height),
                    ImageLockMode.WriteOnly,
                    _bmp.PixelFormat
                );

                try
                {
                    unsafe
                    {
                        byte* ptr = (byte*)bmpData.Scan0;
                        int stride = bmpData.Stride;
                        int length = data.Length;

                        for (int index = 0; index < length; index++)
                        {
                            byte value = data[index];

                            int sy = index / sensorWidth;
                            int sx = index - (sy * sensorWidth);

                            int dy = sy / 2;
                            int dx = (sx * 2) + (sy % 2);

                            ptr[dx + (dy * stride)] = value;
                        }
                    }
                }
                finally
                {
                    _bmp.UnlockBits(bmpData);
                }
            }
        }

        private static void Cleanup()
        {
            try
            {
                if (_device != null)
                {
                    if (_device.IsOpen)
                    {
                        if (_device is IUsbDevice wholeDevice)
                        {
                            wholeDevice.ReleaseInterface(0);
                        }
                        _device.Close();
                    }
                    _device = null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Errore durante il rilascio delle risorse USB: {ex.Message}");
            }

            if (_mainForm != null && !_mainForm.IsDisposed)
            {
                _mainForm.BeginInvoke(new Action(() => _mainForm.Close()));
            }

            Console.WriteLine("Applicazione terminata.");
        }
    }
}
