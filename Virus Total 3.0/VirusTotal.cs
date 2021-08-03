using System;
using RestSharp;
using System.Linq;
using System.Threading;
using Newtonsoft.Json.Linq;
using Virus_Total_3._0.Exceptions;

namespace Virus_Total_3._0
{
	class VirusTotal
	{
		private const string apiUrl = "https://www.virustotal.com/api/v3/";
		private RestClient client;

		private void isLog(bool log, string id, JObject resp)
		{
			if (log)
			{
				string fileName = id + ".json";
				utils.writeLog(fileName, resp);
			}
		}

		public VirusTotal(string apiKey)
		{
			this.client = new RestClient(apiUrl);
			this.client.AddDefaultHeader("x-apikey", apiKey);
		}

		public JObject checkApiKey()
		{
			JObject resp = this.urlScan(apiUrl, true);

			try
			{
				JToken data = resp["data"].Value<JToken>();
			}
			catch (ArgumentNullException)
			{
				string code = resp["error"]["code"].Value<string>();
				string message = resp["error"]["message"].Value<string>();

				switch (code)
				{
					case "AuthenticationRequiredError":
						throw new AuthenticationRequiredError(message);

					case "WrongCredentialsError":
						throw new WrongCredentialsError(message);

					case "UserNotActiveError":
						throw new UserNotActiveError(message);
				}
			}

			return resp;
		}

		public JObject fileScan(string fileName, string url = null)
		{
			string pathh = "files";

			if (url != null)
			{
				pathh = url;
			}

			RestRequest path = new RestRequest(pathh);
			path.AddFile("file", fileName);
			IRestResponse response = client.Post(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			return resp;
		}

		public string fileUpload()
		{
			RestRequest path = new RestRequest("files/upload_url");
			IRestResponse response = client.Get(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			string url = resp["data"].Value<string>();
			return url;
		}

		public JObject fileScanID(string id, bool log = false, bool wait = false)
		{
			id = utils.checkID(id);
			RestRequest path = new RestRequest("files/" + id);

			if (wait)
			{
				Thread.Sleep(30000);
			}

			IRestResponse response = client.Get(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);

			try
			{
				JToken data = resp["data"].Value<JToken>();
			}
			catch (ArgumentNullException)
			{
				string message = resp["error"]["message"].Value<string>();
				throw new NotFoundError(message);
			}

			int scanLength = resp["data"]["attributes"]["last_analysis_results"].Count();

			if (scanLength == 0)
			{
				throw new ScanNotCompleted("Scan not completed");
			}

			isLog(log, id, resp);
			return resp;
		}

		public JObject urlScan(string url, bool is_check = false)
		{
			RestRequest path = new RestRequest("urls");
			path.AddParameter("url", url);
			IRestResponse response = client.Post(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);

			if (!is_check)
			{
				try
				{
					JToken data = resp["data"].Value<JToken>();
				}
				catch (ArgumentNullException)
				{
					string message = resp["error"]["message"].Value<string>();
					throw new InvalidArgumentError(message);
				}
			}

			return resp;
		}

		public JObject urlScanID(string id, bool log = false)
		{
			id = utils.checkID(id);
			RestRequest path = new RestRequest("urls/" + id);
			IRestResponse response = client.Get(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			isLog(log, id, resp);
			return resp;
		}

		public JObject urlAnalyseID(string id)
		{
			id = utils.checkID(id);
			RestRequest path = new RestRequest("urls/" + id + "/analyse");
			IRestResponse response = client.Post(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			return resp;
		}

		public JObject urlLocation(string id, bool log = false)
		{
			id = utils.checkID(id);
			RestRequest path = new RestRequest("urls/" + id + "/network_location");
			IRestResponse response = client.Get(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			isLog(log, id, resp);
			return resp;
		}

		public JObject domain(string domain, bool log = false)
		{
			RestRequest path = new RestRequest("domains/" + domain);
			IRestResponse response = client.Get(path);
			string responseString = response.Content;

			if (response.StatusDescription == "Not Found")
			{
				throw new InvalidArgumentError(responseString);
			}

			JObject resp = JObject.Parse(responseString);

			try
			{
				JToken data = resp["data"].Value<JToken>();
			}
			catch (ArgumentNullException)
			{
				string message = resp["error"]["message"].Value<string>();
				throw new InvalidArgumentError(message);
			}

			isLog(log, domain, resp);
			return resp;
		}

		public JObject ip(string ip, bool log = false)
		{
			RestRequest path = new RestRequest("ip_addresses/" + ip);
			IRestResponse response = client.Get(path);
			string responseString = response.Content;

			if (response.StatusDescription == "Not Found")
			{
				throw new InvalidArgumentError(responseString);
			}

			JObject resp = JObject.Parse(responseString);

			try
			{
				JToken data = resp["data"].Value<JToken>();
			}
			catch (ArgumentNullException)
			{
				string message = resp["error"]["message"].Value<string>();
				throw new InvalidArgumentError(message);
			}

			isLog(log, ip, resp);
			return resp;
		}

		public JObject analyse(string id, bool log = false)
		{
			id = utils.checkID(id);
			RestRequest path = new RestRequest("analyses/" + id);
			IRestResponse response = client.Get(path);
			string responseString = response.Content;
			JObject resp = JObject.Parse(responseString);
			isLog(log, id, resp);
			return resp;
		}
	}
}
