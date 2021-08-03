using System;

namespace Virus_Total_3._0
{
	class UserNotActiveError : Exception
	{
		public UserNotActiveError()
		{

		}

		public UserNotActiveError(string message) : base(message)
		{

		}

		public UserNotActiveError(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
