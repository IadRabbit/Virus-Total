using System;

namespace Virus_Total_3._0
{
	class WrongCredentialsError : Exception
	{
		public WrongCredentialsError()
		{

		}

		public WrongCredentialsError(string message) : base(message)
		{

		}

		public WrongCredentialsError(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
