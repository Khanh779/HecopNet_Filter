using HecopNet_Filter;
using System.Net;

namespace WinFormsApp1;

public partial class Form1 : Form
{
    public Form1()
    {
        InitializeComponent();

    }


    private void button1_Click(object sender, EventArgs e)
    {
        var firewall = new FirewallBuilder()
        .Block()
        .IpAddress(IPAddress.Parse("123.30.175.29"))
        .Build();


    }

    private void button2_Click(object sender, EventArgs e)
    {


    }
}
