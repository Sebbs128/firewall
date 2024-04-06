using MaxMind.GeoIP2;

namespace Yarp.Extensions.Firewall.GeoIP;

/// <summary>
/// Manages lifetime of a given MaxMind GeoIP2 database reader.
/// </summary>
/// <remarks>
/// The underlying GeoIP2.DatabaseReader should be reused, as creation of it is expensive.
/// However, we need to ensure that it isn't disposed should the database path be changed while an Evaluator is using it.
/// To this end, IDisposable is implemented on this class as a means of tracking possible references.
/// Get() increments the reference counter, and Dispose() decrements it.
/// Only the actual owner (currently, the GeoIPDatabaseProviderFactory) can actually cause the DatabaseReader to be disposed,
/// which is done by trigging a cancellation of the provided CancellationToken.
/// </remarks>
public sealed class GeoIPDatabaseProvider : IDisposable
{
    private readonly DatabaseReader _databaseReader;
    private readonly CancellationToken _disposeToken;
    private readonly CancellationTokenRegistration _disposeTokenRegistration;
    private uint _references;
    private bool _dbReaderDisposed;

    internal GeoIPDatabaseProvider(DatabaseReader databaseReader, CancellationToken disposeToken)
    {
        _databaseReader = databaseReader;
        _disposeToken = disposeToken;
        _disposeTokenRegistration = _disposeToken.Register(DisposeIfCancllationRequested);
    }

    /// <summary>
    /// Returns the current GeoIP2 database reader.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="ObjectDisposedException"></exception>
    public IGeoIP2DatabaseReader Get()
    {
        if (_dbReaderDisposed)
            throw new ObjectDisposedException(nameof(GeoIPDatabaseProvider));

        Interlocked.Increment(ref _references);
        return _databaseReader;
    }

    private void DisposeIfCancllationRequested()
    {
        if (_references == 0 && !_dbReaderDisposed && _disposeToken.IsCancellationRequested)
        {
            try
            {
                _databaseReader.Dispose();
                _disposeTokenRegistration.Dispose();
                _dbReaderDisposed = true;
            }
            // something has already disposed _databaseReader
            catch (ObjectDisposedException)
            {
                _dbReaderDisposed = true;
            }
            // allow any other error to bubble up
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!_dbReaderDisposed)
        {
            Interlocked.Decrement(ref _references);
            DisposeIfCancllationRequested();
        }
    }
}
