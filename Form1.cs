using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Threading;

namespace SimpleSniffer
{
    public partial class Form1 : Form
    {
        private ICaptureDevice device;
        private List<RawCapture> PacketQueue = new List<RawCapture>();
        private Queue<PacketShow> packetStrings;
        private Queue<PacketShow> packetShowStrings;
        private int Count = 0;
        private BindingSource bs;
        private int deviceNumber = 0;
        public class PacketShow
        {
            public RawCapture p;
            public int Count { get; private set; }
            public PosixTimeval Timeval { get { return p.Timeval; } }
            public int Length { get { return p.Data.Length; }  }
            public string Protocal { get; set; }
            public string ipProtocal { get; set; }
            public string srcIP { get; set; }
            public string destIP { get; set; }
            public string srcMAC { get; set; }
            public string destMAC { get; set; }
            public PacketShow(int count, RawCapture p)
            {
                srcIP = null;
                destIP = null;
                srcMAC = null;
                destMAC = null;
                this.Count = count;
                this.p = p;
                var packet = PacketDotNet.Packet.ParsePacket(p.LinkLayerType, p.Data);
                var ep = (PacketDotNet.EthernetPacket)packet.Extract<PacketDotNet.EthernetPacket>();
                if (ep != null)
                {
                    Protocal = "Ethernet";
                    srcMAC = ep.SourceHardwareAddress.ToString();
                    destMAC = ep.DestinationHardwareAddress.ToString();
                }
                var ipPacket = (PacketDotNet.IPPacket)packet.Extract<PacketDotNet.IPPacket>();
                if (ipPacket != null)
                {
                    if (ipPacket.Version == IPVersion.IPv4)
                    {
                        ipProtocal = "IPv4";
                    }
                    if (ipPacket.Version == IPVersion.IPv6)
                    {
                        ipProtocal = "IPv6";
                    }
                    ipProtocal = ipPacket.Version.ToString();
                    srcIP = ipPacket.SourceAddress.ToString();
                    destIP = ipPacket.DestinationAddress.ToString();
                    var tcpPacket = (PacketDotNet.TcpPacket)packet.Extract<PacketDotNet.TcpPacket>();
                    if (tcpPacket != null)
                    {
                        Protocal = "TCP";
                        
                    }
                    var udp = (PacketDotNet.UdpPacket)packet.Extract<PacketDotNet.UdpPacket>();
                    if(udp != null)
                    {
                        Protocal = "UDP";
                    }
                    var icmpv4 = (PacketDotNet.IcmpV4Packet)packet.Extract<PacketDotNet.IcmpV4Packet>();
                    if(icmpv4 != null)
                    {
                        ipProtocal = "ICMPv4";
                    }
                    var icmpv6 = (PacketDotNet.IcmpV6Packet)packet.Extract<PacketDotNet.IcmpV6Packet>();
                    if (icmpv6 != null)
                    {
                        ipProtocal = "ICMPv6";
                    }
                }
            }
        }
        public Form1()
        {
            InitializeComponent();
        }
        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            deviceNumber = comboBox1.SelectedIndex;
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            var devices = LibPcapLiveDeviceList.Instance;
            foreach (var dev in devices)
            {
                comboBox1.Items.Add(dev.Description);
            }
            comboBox2.Items.Add("All");
            comboBox2.Items.Add("Ethernet");
            comboBox2.Items.Add("TCP");
            comboBox2.Items.Add("UDP");
            comboBox2.Items.Add("ICMPv4");
            comboBox2.Items.Add("ICMPv6");
            dataGridView1.ReadOnly= true;
            dataGridView1.BackgroundColor = Color.White;
            dataGridView1.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            dataGridView1.MultiSelect = false;
        }
        private void StartCapture()
        {
            Count = 0;
            packetStrings = new Queue<PacketShow>();
            bs = new BindingSource();
            dataGridView1.DataSource = bs;
            device = CaptureDeviceList.Instance[deviceNumber];
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);
            int readTimeoutMilliseconds = 500;
            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);
            device.StartCapture();
        }
        private void EndCapture()
        {
            if (device != null)
            {
                device.StopCapture();
                device.Close();
                
                device.OnPacketArrival -= device_OnPacketArrival;
                device = null;
            }
        }
        private void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            PacketQueue.Add(rawPacket);
            Count++;
            var newPacketShow = new PacketShow(Count, rawPacket);
            packetStrings.Enqueue(newPacketShow);
            textBox2.Text = "抓包中...... 共抓到了"+Count.ToString()+"个包";
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        }
        private void button1_Click(object sender, EventArgs e)
        {
            dataGridView1.Hide();
            textBox2.Show();
            textBox2.Text = "抓包中...... 共抓到了0个包";
            StartCapture();
        }
        private void button2_Click(object sender, EventArgs e)
        {
            EndCapture();
            textBox2.Hide();
            bs.DataSource = null;
            dataGridView1.Show();
            ModeShow(); 
        }
        private void ModeShow()
        {
            if(packetStrings == null)
            {
                return;
            }
            packetShowStrings = new Queue<PacketShow>();
            if (mode == 0)
            {
                if (packetStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetStrings;
            }
            if (mode == 1) //Ethernet
            {
                foreach (var packet in packetStrings)
                {
                    if (packet.Protocal == "Ethernet")
                    {
                        packetShowStrings.Enqueue(packet);
                    }
                }
                if (packetShowStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetShowStrings;
            }
            if (mode == 2) //TCP
            {
                foreach (var packet in packetStrings)
                {
                    if (packet.Protocal == "TCP")
                    {
                        packetShowStrings.Enqueue(packet);
                    }
                }
                if (packetShowStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetShowStrings;
            }
            if (mode == 3) //UDP
            {
                foreach (var packet in packetStrings)
                {
                    if (packet.Protocal == "UDP")
                    {
                        packetShowStrings.Enqueue(packet);
                    }
                }
                if (packetShowStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetShowStrings;
            }
            if (mode == 4) //ICMPv4
            {
                foreach (var packet in packetStrings)
                {
                    if (packet.ipProtocal == "ICMPv4")
                    {
                        packetShowStrings.Enqueue(packet);
                    }
                }
                if (packetShowStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetShowStrings;
            }
            if (mode == 5) //ICMPv6
            {
                foreach (var packet in packetStrings)
                {
                    if (packet.ipProtocal == "ICMPv6")
                    {
                        packetShowStrings.Enqueue(packet);
                    }
                }
                if (packetShowStrings.Count == 0)
                {
                    dataGridView1.Hide();
                    textBox2.Show();
                    textBox2.Text = "没有抓到此种类型的包";
                    return;
                }
                dataGridView1.Show();
                textBox2.Hide();
                bs.DataSource = packetShowStrings;
            }
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }

        private void dataGridView1_SelectionChanged(object sender, EventArgs e)
        {
            if (dataGridView1.SelectedCells.Count == 0)
                return;
            if (packetStrings.Count == 0)
                return;
            if (mode != 0 && packetShowStrings.Count == 0)
                return;
            var packetShow = (PacketShow)dataGridView1.Rows[dataGridView1.SelectedCells[0].RowIndex].DataBoundItem;
            var packet = Packet.ParsePacket(packetShow.p.LinkLayerType, packetShow.p.Data);
            textBox1.Text = packet.ToString();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            EndCapture();
        }
        private int mode;
        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {
            mode = comboBox2.SelectedIndex;
            ModeShow();
        }
    }
}
