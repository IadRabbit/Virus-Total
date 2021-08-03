namespace Virus_Total_3._0
{
	class EngineUDI
	{
		public string category { get; }
		public string engine_name { get; }
		public string method { get; }
		public string result { get; }

		public EngineUDI /* Url Domain Ip */(
			string category, string engine_name,
			string method, string result
		)
		{
			this.category = category;
			this.engine_name = engine_name;
			this.method = method;
			this.result = result;
		}
	}
}
