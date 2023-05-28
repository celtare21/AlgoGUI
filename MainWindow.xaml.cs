using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace AlgoGUI2;

public partial class MainWindow
{
    private byte[]? _privateKey;
    private byte[]? _publicKey;

    public MainWindow()
    {
        InitializeComponent();

        btnGenerateKeys.Click += BtnGenerateKeys_Click;
        btnLoadKeys.Click += BtnLoadKeys_Click;
        btnEncrypt.Click += BtnEncrypt_Click;
        btnDecrypt.Click += BtnDecrypt_Click;
        btnExportKeys.Click += BtnExportKeysOnClick;
    }

    private void BtnExportKeysOnClick(object sender, RoutedEventArgs e)
    {
        if (_privateKey == null || _publicKey == null)
        {
            MessageBox.Show("Please generate or load encryption keys.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var publicKeyString = BitConverter.ToString(_publicKey);
        var privateKeyString = BitConverter.ToString(_privateKey);

        ExportKeysToFile(privateKeyString, publicKeyString);
    }

    private void BtnGenerateKeys_Click(object sender, RoutedEventArgs e)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            _publicKey = rsa.ExportRSAPublicKey();
            _privateKey = rsa.ExportPkcs8PrivateKey();

            var publicKeyString = Array.ConvertAll(BitConverter.ToString(_publicKey).Split('-') ?? throw new InvalidOperationException(), s => Convert.ToByte(s, 16));
            var privateKeyString = Array.ConvertAll(BitConverter.ToString(_privateKey).Split('-') ?? throw new InvalidOperationException(), s => Convert.ToByte(s, 16));
            txtPublicKey.Text = $"{publicKeyString[21..59]}...";
            txtPrivateKey.Text = $"{privateKeyString[21..59]}...";
        }
    }

    private void BtnLoadKeys_Click(object sender, RoutedEventArgs e)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            var fileKeys = ImportKeysFromFile();

            txtPrivateKey.Text = fileKeys.privateKey;
            txtPublicKey.Text = fileKeys.publicKey;

            var importPrivateKey = Array.ConvertAll(fileKeys.privateKey?.Split('-') ?? throw new InvalidOperationException(), s => Convert.ToByte(s, 16));
            var importPublicKey = Array.ConvertAll(fileKeys.publicKey?.Split('-') ?? throw new InvalidOperationException(), s => Convert.ToByte(s, 16));

            rsa.ImportPkcs8PrivateKey(importPrivateKey.AsSpan(), out var _);
            rsa.ImportRSAPublicKey(importPublicKey.AsSpan(), out var _);

            _privateKey = importPrivateKey;
            _publicKey = importPublicKey;
        }
    }

    private void BtnEncrypt_Click(object sender, RoutedEventArgs e)
    {
        if (_publicKey == null)
        {
            MessageBox.Show("Please generate or load encryption keys.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var inputText = txtInput.Text;

        if (string.IsNullOrEmpty(inputText))
        {
            MessageBox.Show("Please enter text to encrypt.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        // Use OaepSHA256 as encryption padding.
        var inputBytes = Encoding.UTF8.GetBytes(inputText);
        var encryptedBytes = RsaEncrypt(inputBytes, _publicKey, true);
        var encryptedText = Convert.ToBase64String(encryptedBytes ?? throw new InvalidOperationException());

        txtEncrypted.Text = encryptedText;
        txtDecrypted.Clear();
    }

    private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
    {
        if (_privateKey == null)
        {
            MessageBox.Show("Please generate or load encryption keys.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var inputText = txtEncrypted.Text;

        if (string.IsNullOrEmpty(inputText))
        {
            MessageBox.Show("Please encrypt text first to decrypt it.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        byte[] encryptedBytes = Convert.FromBase64String(inputText);
        byte[]? decryptedBytes = RsaDecrypt(encryptedBytes, _privateKey, true);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes ?? throw new InvalidOperationException());

        txtDecrypted.Text = decryptedText;
    }

    private static byte[]? RsaEncrypt(byte[] dataToEncrypt, byte[] publicKey, bool doOaepPadding)
    {
        try
        {
            byte[]? encryptedData;

            using (var rsa = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This only needs
                //to include the public key information.
                rsa.ImportRSAPublicKey(publicKey.AsSpan(), out var _);

                //Encrypt the passed byte array and specify OAEP padding.
                //OAEP padding is only available on Microsoft Windows XP or
                //later.
                encryptedData = rsa.Encrypt(dataToEncrypt, doOaepPadding);
            }

            return encryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);

            return null;
        }
    }

    private static byte[]? RsaDecrypt(byte[] dataToDecrypt, byte[] privateKey, bool doOaepPadding)
    {
        try
        {
            byte[]? decryptedData;

            using (var rsa = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This needs
                //to include the private key information.
                rsa.ImportPkcs8PrivateKey(privateKey.AsSpan(), out var _);

                //Decrypt the passed byte array and specify OAEP padding.
                //OAEP padding is only available on Microsoft Windows XP or
                //later.
                decryptedData = rsa.Decrypt(dataToDecrypt, doOaepPadding);
            }

            return decryptedData;
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());

            return null;
        }
    }

    private static void ExportKeysToFile(string privateKey, string publicKey)
    {
        try
        {
            var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "rsa_keys.txt");

            using (var writer = new StreamWriter(file))
            {
                writer.WriteLine(privateKey);
                writer.WriteLine("NEWLINE");
                writer.WriteLine(publicKey);
            }

            MessageBox.Show($"Keys exported to {file}", "Keys Exported");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error exporting keys: {ex.Message}", "Error");
        }
    }

    private static (string? privateKey, string? publicKey) ImportKeysFromFile()
    {
        try
        {
            var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "rsa_keys.txt");

            using (var reader = new StreamReader(file))
            {
                var data = reader.ReadToEnd();

                var keys = data.Split("NEWLINE");

                return (keys[0].Replace("\r\n", string.Empty), keys[1].Replace("\r\n", string.Empty));
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error exporting keys: {ex.Message}", "Error");
        }

        return (null, null);
    }
}