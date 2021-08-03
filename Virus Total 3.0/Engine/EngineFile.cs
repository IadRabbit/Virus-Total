namespace Virus_Total_3._0
{
	class EngineFile
	{
		public string category { get; }
		public string engine_name { get; }
		public string engine_update { get; }
		public string engine_version { get; }
		public string method { get; }
		public string result { get; }

		public EngineFile(
			string category, string engine_name,
			string engine_update, string engine_version,
			string method, string result
		)
		{
			this.category = category;
			this.engine_name = engine_name;
			this.engine_update = engine_update;
			this.engine_version = engine_version;
			this.method = method;
			this.result = result;
		}
	}
}
