using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TimeCryptor.Utils
{
  public static class Logger
  {
    public static void Log(string msg, bool newline = true, bool logtime = false)
    {
      Console.Write($@"{(logtime ? DateTime.Now.ToString("HH:mm:ss.fff") : string.Empty)} - {msg}" + (newline ? Environment.NewLine : string.Empty));
    }
  }
}
