using Microsoft.Win32;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace FEW_Engine;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    String[] FilePaths = Array.Empty<string>();
    String[] FileNames = Array.Empty<string>();

    private void Button_Original_File_Click(object sender, RoutedEventArgs e)
    {
        OpenFileDialog ofd = new OpenFileDialog();
        ofd.FileName = "";
        ofd.Multiselect = true;
        ofd.Filter = "Definition file (*_define.*)|*_define.*|Script file (*_sce.*)|*_sce.*";
        ofd.FilterIndex = ofd.Filter.Length;
        Nullable<bool> result = ofd.ShowDialog();

        if (result == true)
        {
            try
            {
                //Copy the values for the selected files to an array in order to manage the
                //files later on according to their extension
                FilePaths = (string[])ofd.FileNames.Clone();
                FileNames = new string[FilePaths.Length];
                for (int CurrentFile = 0; CurrentFile < ofd.FileNames.Length; CurrentFile++)
                {
                    FileNames[CurrentFile] = System.IO.Path.GetFileNameWithoutExtension(ofd.FileNames[CurrentFile]);
                }

                Button_Convert.IsEnabled = false;

                for (int CurrentFile = 0; CurrentFile < FilePaths.Length; CurrentFile++)
                {
                    string OriginalFileExtension = System.IO.Path.GetExtension(FilePaths[CurrentFile]);

                    //Check to see if the file is one that is not compatible with the program
                    if (OriginalFileExtension != ".txt" && OriginalFileExtension != ".dat")
                    {
                        MessageBox.Show($"At least one of the selected files is not designed to be handled by this program, and thus" +
                            $" the conflicting files will not be processed.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                        break;
                    }

                    //Activate the button to convert the selected files because we know that there's
                    //already one that has a compatible extension
                    Button_Convert.IsEnabled = true;
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void Button_Convert_Click(object sender, RoutedEventArgs e)
    {
        OpenFolderDialog ofd = new OpenFolderDialog();
        Nullable<bool> result = ofd.ShowDialog();

        if (result == true)
        {
            try
            {
                for (int CurrentFile = 0; CurrentFile < FilePaths.Length; CurrentFile++)
                {
                    Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                    Encoding shiftJIS = Encoding.GetEncoding("shift-jis");

                    //Check what name and extension the file has, in order to choose its corresponding class
                    if (System.IO.Path.GetExtension(FilePaths[CurrentFile]) == ".dat"
                        && System.IO.Path.GetFileNameWithoutExtension(FilePaths[CurrentFile]).EndsWith("_sce"))
                    {
                        byte[] Data = File.ReadAllBytes(FilePaths[CurrentFile]);
                        Dat dat = new Dat();
                        byte[] DecryptedFile = dat.Decrypt(Data);
                        File.WriteAllBytes(ofd.FolderName + "\\" + FileNames[CurrentFile] + "_metadata.dat", dat.ObtainBinaryInstructions(DecryptedFile));
                        File.WriteAllText(ofd.FolderName + "\\" + FileNames[CurrentFile] + ".txt", dat.Parse(DecryptedFile), shiftJIS);
                    }

                    //WIP TO PARSE
                    if (System.IO.Path.GetExtension(FilePaths[CurrentFile]) == ".dat"
                        && System.IO.Path.GetFileNameWithoutExtension(FilePaths[CurrentFile]).EndsWith("_define"))
                    {
                        byte[] Data = File.ReadAllBytes(FilePaths[CurrentFile]);
                        Dat dat = new Dat();
                        byte[] DecryptedFile = dat.Decrypt(Data);
                        File.WriteAllBytes(ofd.FolderName + "\\" + FileNames[CurrentFile] + ".dat", DecryptedFile);
                        //File.WriteAllText(ofd.FolderName + "\\" + FileNames[CurrentFile] + ".txt", dat.Parse(DecryptedFile), shiftJIS);
                    }
                    else if (System.IO.Path.GetExtension(FilePaths[CurrentFile]) == ".txt"
                        && System.IO.Path.GetFileNameWithoutExtension(FilePaths[CurrentFile]).EndsWith("_sce"))
                    {
                        //It checks to see if the raw binary data of the script that is unparsed is present in the same
                        //directory
                        if (System.IO.File.Exists(
                            System.IO.Path.GetDirectoryName(FilePaths[CurrentFile])
                            + "\\" + System.IO.Path.GetFileNameWithoutExtension(FileNames[CurrentFile]) + "_metadata.dat"))
                        {
                            string[] Data = File.ReadAllLines(FilePaths[CurrentFile], shiftJIS);
                            byte[] BinaryInstructions = File.ReadAllBytes(System.IO.Path.GetDirectoryName(FilePaths[CurrentFile])
                            + "\\" + System.IO.Path.GetFileNameWithoutExtension(FileNames[CurrentFile]) + "_metadata.dat");
                            Dat dat = new Dat();
                            File.WriteAllBytes(ofd.FolderName + "\\" + FileNames[CurrentFile] + ".dat", dat.Encrypt(Data, BinaryInstructions));
                        }
                        else
                        {
                            throw new Exception("The metadata file for the reconstruction of the compressed files" +
                                        " is missing, make sure to regenerate it by uncompressing again the original files");
                        }
                    }
                }
                Button_Convert.IsEnabled = false;
                MessageBox.Show($"Process completed successfully.", "Conversion completed.", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}