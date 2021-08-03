using System;
using System.IO;

namespace Virus_Total_3._0
{
	class File
	{
		private string fileName;

		public File(string fileName)
		{
			this.fileName = fileName;
		}

		public string read()
		{
			FileStream file = new FileStream(this.fileName, FileMode.Open, FileAccess.Read);
			StreamReader reading = new StreamReader(file);
			string content = reading.ReadToEnd();
			reading.Close();
			file.Close();
			return content;
		}

		public void write(string data)
		{
			FileStream file;

			try
			{
				file = new FileStream(this.fileName, FileMode.Create, FileAccess.Write);
			}
			catch (UnauthorizedAccessException)
			{
				System.IO.File.Delete(this.fileName);
				file = new FileStream(this.fileName, FileMode.Create, FileAccess.Write);
			}

			StreamWriter writing = new StreamWriter(file);
			writing.Write(data);
			writing.Flush();
			writing.Close();
			file.Close();
		}

		public void hide()
		{
			FileInfo file = new FileInfo(this.fileName);
			file.Attributes = FileAttributes.Hidden;
		}

		public string getFileName()
		{
			string fileName = Path.GetFileName(this.fileName);
			return fileName;
		}

		public long getSize()
		{
			long size = new FileInfo(this.fileName).Length;
			return size;
		}
	}
}
