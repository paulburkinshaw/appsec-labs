using System.Diagnostics;

namespace Insecure.Web.Util
{
    public class PluginLoader
    {
        public string Path
        {
            set { Process.Start(value); }
        }
    }

}
