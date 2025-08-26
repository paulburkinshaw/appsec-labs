

namespace Insecure.Web.Util
{
    // TODO: Find out if this class is still needed or if it can be replaced now we are using the ASP.NET Core logging framework.
    public class CustomLogger
    {
        public string? LogfilePath { get; set; }

        public string LogfileContents
        {
            get
            {
                if(string.IsNullOrEmpty(LogfilePath))
                    throw new ArgumentNullException(nameof(LogfilePath));

                var logContentsStr = File.ReadAllText(LogfilePath);
                if (string.IsNullOrEmpty(logContentsStr))
                    throw new FileNotFoundException("Log file is empty or does not exist.", LogfilePath);
               
                return logContentsStr;
            }
        }

        public void WriteToLogFile(string logfilePath, string logFileBody)
        {
            if (!string.IsNullOrEmpty(logfilePath))
                File.WriteAllText(logfilePath, logFileBody);
        }

    }

}
