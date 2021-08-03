using System;

namespace Virus_Total_3._0.Exceptions
{
	class NotFoundError : Exception
	{
		public NotFoundError()
		{

		}

		public NotFoundError(string message) : base(message)
		{

		}

		public NotFoundError(string message, Exception inner)
			: base(message, inner)
		{

		}
	}
}
