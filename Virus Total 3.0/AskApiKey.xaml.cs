using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Virus_Total_3._0
{
	/// <summary>
	/// Logica di interazione per AskApiKey.xaml
	/// </summary>
	public partial class AskApiKey : Window
	{
		private bool notapikey = true;

		public AskApiKey()
		{
			InitializeComponent();
		}

		private void btnApiKey_Click(object sender, RoutedEventArgs e)
		{
			string apikey = txtApiKey.Text;
			VirusTotal api = new VirusTotal(apikey);

			try
			{
				api.checkApiKey();
			}
			catch (AuthenticationRequiredError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblInsertApiKey.Focus();
				return;
			}
			catch (WrongCredentialsError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblInsertApiKey.Focus();
				return;
			}
			catch (UserNotActiveError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblInsertApiKey.Focus();
				return;
			}

			string fileName = utils.apikeyIni;
			string data = "[virustotal]\n\napikey = " + apikey;
			File file = new File(fileName);
			file.write(data);
			file.hide();
			MessageBox.Show("The ApiKey works", "SUCCESS", MessageBoxButton.OK, MessageBoxImage.Information);
			this.notapikey = false;
			frmAskApiKey.Close();
		}

		private void OpenLinkIDKApiKey(object sender, MouseButtonEventArgs e)
		{
			Process.Start(utils.linkHelp);
		}

		private void changeColorRed(object sender, MouseEventArgs e)
		{
			lblIDKApiKey.Foreground = Brushes.Red;
		}

		private void changeColorBlue(object sender, MouseEventArgs e)
		{
			lblIDKApiKey.Foreground = Brushes.Blue;
		}

		private void frmAskApiKey_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			if (this.notapikey)
			{
				MessageBoxResult you = MessageBox.Show("NO WORKING API KEY HAS BEEN FOUND, IF YOU PRESS YES YOU WON'T USE THIS PROGRAM.\nARE YOU SURE?", "ARE YOU SURE?", MessageBoxButton.YesNoCancel);

				if (you == MessageBoxResult.Yes)
				{
					Environment.Exit(1);
				}
				else
				{
					e.Cancel = true;
				}
			}
		}
	}
}
