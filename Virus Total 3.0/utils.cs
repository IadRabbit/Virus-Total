using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace Virus_Total_3._0
{
	class utils
	{
		public static string apikeyIni = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\virustotal.ini";
		public const string linkHelp = "https://developers.virustotal.com/v3.0/reference#getting-started";
		public const long limitSizeFile = 32000000;
		public const long limitSizeFileMax = 200000000;
		public const string filter = "Json Files (*.logVT.json) | *.logVT.json| All Files (*.*) | *.*";

		public static string checkID(string ids)
		{
			if (ids.StartsWith("u-"))
			{
				ids = ids.Split('-')[1];
			}

			else if (ids.EndsWith("=="))
			{
				byte[] plainTextBytes = Convert.FromBase64String(ids);
				ids = System.Text.Encoding.UTF8.GetString(plainTextBytes);
				ids = ids.Split(':')[0];
			}

			return ids;
		}

		public static void writeLog(string path, JObject json)
		{
			string data = JsonConvert.SerializeObject(json, Formatting.Indented);
			File file = new File(path);
			file.write(data);
		}

		public static DateTime getDate(int time)
		{
			DateTime date = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
			date = date.AddSeconds(time).ToLocalTime();
			return date;
		}

		public static string getDateString(DateTime date)
		{
			string dateString = String.Format(
				"{0}/{1}/{2} {3}:{4}:{5}",
				date.Year, date.Month, date.Day,
				date.Hour, date.Minute, date.Second
			);

			return dateString;
		}

		public static string varExcape(string str)
		{
			string stringa = (
				str
				.Replace("\\", "")
				.Replace("/", "")
				.Replace(":", "")
				.Replace("*", "")
				.Replace("?", "")
				.Replace("\"", "")
				.Replace("<", "")
				.Replace(">", "")
				.Replace("|", "")
				.Replace("&", "")
				.Replace(".", "")
			);

			return stringa;
		}
	}
}
