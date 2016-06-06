using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Skryptonite;
using System.Threading.Tasks;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace Skryptonite.Sample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void OptimizeButton_Tapped(object sender, TappedRoutedEventArgs e)
        {
            //var scrypt = await Task.Run(() => Scrypt.CreateOptimal(16 * 1024 * 1024, 5000));
            var scrypt = Scrypt.CreateOptimal(16 * 1024 * 1024, 5000);
            OptimalNTextBlock.Text = scrypt.ProcessingCost.ToString();
            OptimalRTextBlock.Text = scrypt.ElementLengthMultiplier.ToString();
            OptimalPTextBlock.Text = scrypt.Parallelization.ToString();
        }
    }
}
