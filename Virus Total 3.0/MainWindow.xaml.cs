using IniParser;
using System.Windows;
using IniParser.Model;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System.Windows.Media;
using System.Windows.Controls;
using System.Collections.Generic;
using Virus_Total_3._0.Exceptions;

namespace Virus_Total_3._0
{
	/// <summary>
	/// Logica di interazione per MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		private VirusTotal api;
		private JObject log;
		private string scanName;
		private Label[] labelsFile;
		private Label[] labelsURL;
		private Label[] labelsDomain;
		private Label[] labelsIP;

		private Dictionary<int, string> forFile = new Dictionary<int, string>()
		{
			{0, "confirmed-timeout"},
			{1, "failure"},
			{2, "harmless"},
			{3, "malicious"},
			{4, "suspicious"},
			{5, "timeout"},
			{6, "type-unsupported"},
			{7, "undetected"}
		};

		private Dictionary<int, string> forUDI = new Dictionary<int, string>()
		{
			{0, "harmless"},
			{1, "malicious"},
			{2, "suspicious"},
			{3, "timeout"},
			{4, "undetected"}
		};

		public MainWindow()
		{
			InitializeComponent();

			this.labelsFile = new Label[] {
				lblFileConfirmed_timeout, lblFileFailure,
				lblFileHarmless, lblFileMalicious,
				lblFileSuspicious, lblFileTimeout,
				lblFileTypeUnsupported, lblFileUndetected
			};

			this.labelsURL = new Label[]
			{
				lblURLHarmless, lblURLMalicious,
				lblURLSuspicious, lblURLTimeout, lblURLUndetected
			};

			this.labelsDomain = new Label[]
			{
				lblDomainHarmless, lblDomainMalicious,
				lblDomainSuspicious, lblDomainTimeout, lblDomainUndetected
			};

			this.labelsIP = new Label[]
			{
				lblIPHarmless, lblIPMalicious,
				lblIPSuspicious, lblIPTimeout, lblIPUndetected
			};
		}

		private void showAskApiKey()
		{
			AskApiKey win2 = new AskApiKey();
			win2.ShowDialog();
		}

		private void check()
		{
			if (
				!System.IO.File.Exists(utils.apikeyIni)
			)
			{
				showAskApiKey();
			}

			FileIniDataParser parser = new FileIniDataParser();
			IniData data = parser.ReadFile(utils.apikeyIni);
			string apikey = data["virustotal"]["apikey"];
			this.api = new VirusTotal(apikey);

			try
			{
				api.checkApiKey();
			}
			catch (AuthenticationRequiredError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				showAskApiKey();
				check();
			}
			catch (WrongCredentialsError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				showAskApiKey();
				check();
			}
			catch (UserNotActiveError error)
			{
				MessageBox.Show(error.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				showAskApiKey();
				check();
			}
		}

		private void reset(Visibility mode, Label[] labels)
		{
			btnSaveLog.Visibility = mode;

			foreach (Label a in this.labelsDomain)
			{
				a.Visibility = mode;
			}
		}

		private void startup(object sender, RoutedEventArgs e)
		{
			mainGrid.Visibility = Visibility.Hidden;
			check();
			reset(Visibility.Hidden, this.labelsFile);
			reset(Visibility.Hidden, this.labelsURL);
			reset(Visibility.Hidden, this.labelsDomain);
			reset(Visibility.Hidden, this.labelsIP);
			mainGrid.Visibility = Visibility.Visible;
		}

		private void addToDataFile(JObject json)
		{
			lstScanGoodFile.Items.Clear();
			lstScanBadFile.Items.Clear();
			JToken results = json["data"]["attributes"];
			JToken analysisResults = results["last_analysis_results"];

			foreach (JToken a in analysisResults)
			{
				JToken c = a.First;
				string category = c["category"].Value<string>();
				string engine_name = c["engine_name"].Value<string>();
				string engine_update = c["engine_update"].Value<string>();
				string engine_version = c["engine_version"].Value<string>();
				string method = c["method"].Value<string>();
				string result = c["result"].Value<string>();

				EngineFile scan = new EngineFile(
					category, engine_name, engine_update,
					engine_version, method, result
				);

				if (category == "undetected")
				{
					lstScanGoodFile.Items.Add(scan);
				}
				else
				{
					lstScanBadFile.Items.Add(scan);
				}
			}

			JToken analysisStats = results["last_analysis_stats"];

			foreach (KeyValuePair<int, string> a in forFile)
			{
				int index = a.Key;
				Label cLabel = this.labelsFile[index];
				string value = a.Value;
				string content = value + ": " + analysisStats[value];
				cLabel.Content = content;
			}

			string dateModificationDate = utils.getDateString(
				utils.getDate(
					results["last_modification_date"].Value<int>()
				)
			);

			string dateSubmissionDate = utils.getDateString(
				utils.getDate(
					results["last_submission_date"].Value<int>()
				)
			);

			lblFileLastModificationDate.Content = "Last Modification Date: " + dateModificationDate;
			lblFileLastSubmissionDate.Content = "Last Submission Date: " + dateSubmissionDate;
		}

		private void addToDataURL(JObject json)
		{
			lstScanGoodURL.Items.Clear();
			lstScanBadURL.Items.Clear();
			JToken results = json["data"]["attributes"];
			string url = results["url"].Value<string>();
			lblURL.Content = "URL: " + url;
			JToken analysisResults = results["last_analysis_results"];

			foreach (JToken a in analysisResults)
			{
				JToken c = a.First;
				string category = c["category"].Value<string>();
				string engine_name = c["engine_name"].Value<string>();
				string method = c["method"].Value<string>();
				string result = c["result"].Value<string>();

				EngineUDI scan = new EngineUDI(
					category, engine_name,
					method, result
				);

				if (category == "harmless")
				{
					lstScanGoodURL.Items.Add(scan);
				}
				else
				{
					lstScanBadURL.Items.Add(scan);
				}
			}

			JToken analysisStats = results["last_analysis_stats"];

			foreach (KeyValuePair<int, string> a in forUDI)
			{
				int index = a.Key;
				Label cLabel = this.labelsURL[index];
				string value = a.Value;
				string content = value + ": " + analysisStats[value];
				cLabel.Content = content;
			}

			string dateModificationDate = utils.getDateString(
				utils.getDate(
					results["last_modification_date"].Value<int>()
				)
			);

			string dateSubmissionDate = utils.getDateString(
				utils.getDate(
					results["last_submission_date"].Value<int>()
				)
			);

			lblURLLastModificationDate.Content = "Last Modification Date: " + dateModificationDate;
			lblURLLastSubmissionDate.Content = "Last Submission Date: " + dateSubmissionDate;
		}

		private void addToDataDomain(JObject json)
		{
			lstScanGoodDomain.Items.Clear();
			lstScanBadDomain.Items.Clear();
			rtbDomain.Document.Blocks.Clear();
			JToken results = json["data"];
			string domain = results["id"].Value<string>();
			lblDomain.Content = "Domain: " + domain;
			results = results["attributes"];
			JToken analysisResults = results["last_analysis_results"];

			foreach (JToken a in analysisResults)
			{
				JToken c = a.First;
				string category = c["category"].Value<string>();
				string engine_name = c["engine_name"].Value<string>();
				string method = c["method"].Value<string>();
				string result = c["result"].Value<string>();

				EngineUDI scan = new EngineUDI(
					category, engine_name,
					method, result
				);

				if (category == "harmless")
				{
					lstScanGoodDomain.Items.Add(scan);

				}
				else
				{
					lstScanBadDomain.Items.Add(scan);
				}
			}

			JToken analysisStats = results["last_analysis_stats"];

			foreach (KeyValuePair<int, string> a in forUDI)
			{
				int index = a.Key;
				Label cLabel = this.labelsDomain[index];
				string value = a.Value;
				string content = value + ": " + analysisStats[value];
				cLabel.Content = content;
			}

			string dateModificationDate = utils.getDateString(
				utils.getDate(
					results["last_modification_date"].Value<int>()
				)
			);

			lblDomainLastModificationDate.Content = "Last Modification Date: " + dateModificationDate;
			string whoisDate;

			try
			{
				whoisDate = utils.getDateString(
					utils.getDate(
						results["whois_date"].Value<int>()
					)
				);
			}
			catch (System.ArgumentNullException)
			{
				whoisDate = "unknown";
			}

			var whoisInfo = results["whois"].Value<object>().ToString();
			whoisInfo += "\nDate: " + whoisDate;
			rtbDomain.AppendText(whoisInfo);
		}

		private void addToDataIP(JObject json)
		{
			lstScanGoodIP.Items.Clear();
			lstScanBadIP.Items.Clear();
			rtbIP.Document.Blocks.Clear();
			JToken results = json["data"];
			string ip = results["id"].Value<string>();
			lblIP.Content = "IP: " + ip;
			results = results["attributes"];
			JToken analysisResults = results["last_analysis_results"];

			foreach (JToken a in analysisResults)
			{
				JToken c = a.First;
				string category = c["category"].Value<string>();
				string engine_name = c["engine_name"].Value<string>();
				string method = c["method"].Value<string>();
				string result = c["result"].Value<string>();

				EngineUDI scan = new EngineUDI(
					category, engine_name,
					method, result
				);

				if (category == "harmless")
				{
					lstScanGoodIP.Items.Add(scan);

				}
				else
				{
					lstScanBadIP.Items.Add(scan);
				}
			}

			JToken analysisStats = results["last_analysis_stats"];

			foreach (KeyValuePair<int, string> a in forUDI)
			{
				int index = a.Key;
				Label cLabel = this.labelsIP[index];
				string value = a.Value;
				string content = value + ": " + analysisStats[value];
				cLabel.Content = content;
			}

			string dateModificationDate = utils.getDateString(
				utils.getDate(
					results["last_modification_date"].Value<int>()
				)
			);

			lblIPLastModificationDate.Content = "Last Modification Date: " + dateModificationDate;
			string whoisDate;

			try
			{
				whoisDate = utils.getDateString(
					utils.getDate(
						results["whois_date"].Value<int>()
					)
				);
			}
			catch (System.ArgumentNullException)
			{
				whoisDate = "unknown";
			}

			string whoisInfo;

			try
			{
				whoisInfo = results["whois"].Value<string>();
			}
			catch (System.ArgumentNullException)
			{
				whoisInfo = "";
			}

			whoisInfo += "\nDate: " + whoisDate;
			rtbIP.AppendText(whoisInfo);
		}

		private void scanFile(string fileName)
		{
			File file = new File(fileName);
			long fileSize = file.getSize();
			JObject json;

			if (fileSize >= utils.limitSizeFileMax)
			{
				MessageBox.Show("Can't scan file bigger than 200 MB", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				return;
			}

			MessageBox.Show("This is gonna take a bit, don't worry (30 or 60 seconds), (press OK)", "BE PATIENT :)", MessageBoxButton.OK, MessageBoxImage.Information);

			if (fileSize >= utils.limitSizeFile)
			{
				string url = this.api.fileUpload();
				json = this.api.fileScan(fileName, url);
			}
			else
			{
				json = this.api.fileScan(fileName);
			}

			reset(Visibility.Visible, this.labelsFile);
			fileName = file.getFileName();
			lblFileName.Content = "File Name: " + fileName;
			string scanID = json["data"]["id"].Value<string>();
			bool time = false;

			while (true)
			{
				try
				{
					json = this.api.fileScanID(scanID, false, time);
					break;
				}
				catch (NotFoundError)
				{
					time = true;
				}
				catch (ScanNotCompleted)
				{
					time = true;
				}
			}

			this.scanName = fileName + "_" + utils.checkID(scanID);
			this.log = json;
			addToDataFile(json);
		}

		private void scanURL(string url)
		{
			reset(Visibility.Visible, this.labelsURL);
			JObject json;

			try
			{
				json = this.api.urlScan(url);
			}
			catch (InvalidArgumentError)
			{
				MessageBox.Show("Invalid URL", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblURL.Focus();
				return;
			}

			string scanID = json["data"]["id"].Value<string>();
			json = this.api.urlScanID(scanID);
			this.scanName = url;
			this.log = json;
			addToDataURL(json);
		}

		private void scanDomain(string domain)
		{
			reset(Visibility.Visible, this.labelsDomain);
			JObject json;

			try
			{
				json = this.api.domain(domain);
			}
			catch (InvalidArgumentError)
			{
				MessageBox.Show("Invalid Domain", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblDomain.Focus();
				return;
			}

			this.scanName = domain;
			this.log = json;
			addToDataDomain(json);
		}

		private void scanIP(string ip)
		{
			reset(Visibility.Visible, this.labelsIP);
			JObject json;

			try
			{
				json = this.api.ip(ip);
			}
			catch (InvalidArgumentError)
			{
				MessageBox.Show("Invalid IP", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				lblDomain.Focus();
				return;
			}

			this.scanName = ip;
			this.log = json;
			addToDataIP(json);
		}

		private void fileDropped(object sender, DragEventArgs e)
		{
			string[] fileList = (string[])e.Data.GetData(DataFormats.FileDrop, false);
			string fileName = fileList[0];
			scanFile(fileName);
		}

		private void lblDropFileChooseFile(object sender, System.Windows.Input.MouseButtonEventArgs e)
		{
			OpenFileDialog dialog = new OpenFileDialog();
			dialog.ShowDialog();
			string fileName = dialog.FileName;

			if (fileName == "")
			{
				return;
			}

			scanFile(fileName);
		}

		private void btnSaveLog_Click(object sender, RoutedEventArgs e)
		{
			SaveFileDialog save = new SaveFileDialog();
			save.Filter = utils.filter;

			if (
				char.IsLetter(
					this.scanName[
						this.scanName.Length - 1
					]
				)
			)
			{
				save.FileName = utils.varExcape(this.scanName);
			}
			else
			{
				save.FileName = this.scanName;
			}

			save.ShowDialog();
			string fileName = save.FileName;

			if (fileName == "")
			{
				return;
			}

			utils.writeLog(fileName, this.log);
		}

		private void btnURL_Click(object sender, RoutedEventArgs e)
		{
			string url = txtURL.Text;

			if (url == "")
			{
				MessageBox.Show("The field is empty", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				txtURL.Focus();
				return;
			}

			scanURL(url);
		}

		private void btnDomain_Click(object sender, RoutedEventArgs e)
		{
			string domain = txtDomain.Text;

			if (domain == "")
			{
				MessageBox.Show("The field is empty", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				txtDomain.Focus();
				return;
			}

			scanDomain(domain);
		}

		private void btnIP_Click(object sender, RoutedEventArgs e)
		{
			string ip = txtIP.Text;

			if (ip == "")
			{
				MessageBox.Show("The field is empty", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
				txtIP.Focus();
				return;
			}

			scanIP(ip);
		}

		private void btnLoadLog_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dialog = new OpenFileDialog();
			dialog.Filter = utils.filter;
			dialog.ShowDialog();
			string fileName = dialog.FileName;

			if (fileName == "")
			{
				return;
			}

			File file = new File(fileName);
			string content = file.read();
			JObject json = JObject.Parse(content);
			string type = json["data"]["type"].Value<string>();

			switch (type)
			{
				case "file":
					tabAll.SelectedIndex = 0;
					lblFileName.Content = "";
					addToDataFile(json);
					break;
				case "url":
					tabAll.SelectedIndex = 1;
					addToDataURL(json);
					break;
				case "domain":
					tabAll.SelectedIndex = 2;
					addToDataDomain(json);
					break;
				case "ip_address":
					tabAll.SelectedIndex = 3;
					addToDataIP(json);
					break;
			}
		}

		private void changeToBlueTabIFile(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIFile.Foreground = Brushes.Blue;
		}

		private void changeToDarkTabIFile(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIFile.Foreground = Brushes.Black;
		}

		private void changeToDarkTabIUrl(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIUrl.Foreground = Brushes.Black;
		}

		private void changeToBlueTabIUrl(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIUrl.Foreground = Brushes.Blue;
		}

		private void changeToBlueTabIDomain(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIDomain.Foreground = Brushes.Blue;
		}

		private void changeToDarkTabIDomain(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIDomain.Foreground = Brushes.Black;
		}

		private void changeToBlueTabIIP(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIIP.Foreground = Brushes.Blue;
		}

		private void changeToDarkTabIIP(object sender, System.Windows.Input.MouseEventArgs e)
		{
			tabIIP.Foreground = Brushes.Black;
		}
	}
}
