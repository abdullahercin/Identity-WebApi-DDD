namespace Assist.Identity.Domain.ValueObjects;
/// <summary>
/// Value Object Base Class
/// DDD'de value object'lerin ortak davranışlarını tanımlar
/// Value object'ler immutable'dır ve value-based equality kullanır
/// </summary>
public abstract class ValueObject
{
    /// <summary>
    /// Equality comparison için kullanılacak component'leri döner
    /// Her value object kendi component'lerini override etmelidir
    /// </summary>
    /// <returns>Equality comparison'da kullanılacak değerler</returns>
    protected abstract IEnumerable<object?> GetEqualityComponents();

    /// <summary>
    /// Value-based equality comparison
    /// İki value object aynı değerlere sahipse equal'dır
    /// </summary>
    public override bool Equals(object? obj)
    {
        if (obj == null || obj.GetType() != GetType())
            return false;

        var other = (ValueObject)obj;
        return GetEqualityComponents().SequenceEqual(other.GetEqualityComponents());
    }

    /// <summary>
    /// Hash code generation
    /// Equality component'lerin XOR'u alınarak hash code üretilir
    /// </summary>
    public override int GetHashCode()
    {
        return GetEqualityComponents()
            .Select(x => x?.GetHashCode() ?? 0)
            .Aggregate((x, y) => x ^ y);
    }

    /// <summary>
    /// Equality operators
    /// </summary>
    public static bool operator ==(ValueObject left, ValueObject right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(ValueObject left, ValueObject right)
    {
        return !Equals(left, right);
    }
}