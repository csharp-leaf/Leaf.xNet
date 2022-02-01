using System;
using System.IO;
using System.Net.Sockets;

namespace Leaf.xNet
{
    public interface ISslProvider
    {
        bool Disposable { get; }
        Stream Initialize(Uri address, NetworkStream networkStream);
    }
}