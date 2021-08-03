using System;

namespace Virus_Total_3._0
{
	class AuthenticationRequiredError : Exception
	{
		public AuthenticationRequiredError()
		{

		}

		public AuthenticationRequiredError(string message) : base(message)
		{

		}

		public AuthenticationRequiredError(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
