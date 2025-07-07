using System.Buffers;
using System.IO.Pipelines;

namespace Yarp.Extensions.Firewall.Utilities;

// not used. keeping around for reference
internal class CircularBuffer : IDisposable
{
    private readonly IMemoryOwner<byte> _owner;
    private readonly Memory<byte> _window;
    private readonly PipeReader _reader;
    private readonly int _maxChunkSize;

    private ReadResult _readResult = default;

    public CircularBuffer(PipeReader reader, int minBufferSize, int? maxChunkSize = null)
    {
        if (maxChunkSize is not null && minBufferSize < maxChunkSize)
        {
            throw new ArgumentException("maxChunkSize must be less than minBufferSize", nameof(maxChunkSize));
        }

        _owner = MemoryPool<byte>.Shared.Rent(minBufferSize);
        _window = _owner.Memory;
        _reader = reader;
        _maxChunkSize = maxChunkSize ?? _window.Length;
    }

    public bool IsCompleted => _readResult.IsCompleted == true;

    public Span<byte> Span => _window.Span;

    public async Task<bool> ReadNextAsync(CancellationToken cancellationToken = default)
    {
        _readResult = await _reader.ReadAsync(cancellationToken);

        if (_readResult.IsCompleted || _readResult.IsCanceled || _readResult.Buffer.Length == 0)
        {
            return false;
        }

        int bytesToCopy;
        for (int i = 0; i < _readResult.Buffer.Length; i += bytesToCopy)
        {
            bytesToCopy = (int)Math.Min(_readResult.Buffer.Length - i, _maxChunkSize);
            var buffer = _readResult.Buffer.Slice(i, bytesToCopy);

            // slide existing window contents down by bytesToCopy
            _window[bytesToCopy..].CopyTo(_window);

            buffer.CopyTo(_window.Span[(_window.Length - bytesToCopy)..]);
        }

        _reader.AdvanceTo(_readResult.Buffer.Start, _readResult.Buffer.End);
        return true;
    }

    public void Dispose()
    {
        _owner.Dispose();
    }
}
