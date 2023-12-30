namespace Yarp.Extensions.Firewall.Utilities;

internal static class CollectionEqualityHelper
{
    public static bool Equals<T>(IReadOnlyList<T>? list1, IReadOnlyList<T>? list2, IEqualityComparer<T>? valueComparer = null)
    {
        if (ReferenceEquals(list1, list2))
        {
            return true;
        }

        if (list1 is null || list2 is null)
        {
            return false;
        }

        if (list1.Count != list2.Count)
        {
            return false;
        }

        valueComparer ??= EqualityComparer<T>.Default;

        for (var i = 0; i < list1.Count; i++)
        {
            if (!valueComparer.Equals(list1[i], list2[i]))
            {
                return false;
            }
        }

        return true;
    }

    public static int GetHashCode<T>(IReadOnlyList<T>? values, IEqualityComparer<T>? valueComparer = null)
    {
        if (values is null)
        {
            return 0;
        }

        valueComparer ??= EqualityComparer<T>.Default;

        var hashCode = new HashCode();
        foreach (var value in values)
        {
            hashCode.Add(value, valueComparer);
        }
        return hashCode.ToHashCode();
    }
}
