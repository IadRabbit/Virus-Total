using System;

namespace Virus_Total_3._0.Exceptions
{
	class ScanNotCompleted : Exception
	{
		public ScanNotCompleted()
		{

		}

		public ScanNotCompleted(string message) : base(message)
		{

		}

		public ScanNotCompleted(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
