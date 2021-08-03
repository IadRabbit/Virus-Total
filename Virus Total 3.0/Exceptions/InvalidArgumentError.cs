using System;

namespace Virus_Total_3._0.Exceptions
{
	class InvalidArgumentError : Exception
	{
		public InvalidArgumentError()
		{

		}

		public InvalidArgumentError(string message) : base(message)
		{

		}

		public InvalidArgumentError(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
