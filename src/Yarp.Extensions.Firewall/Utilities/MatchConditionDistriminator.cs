using System.Text.Json;
using System.Text.Json.Serialization;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Utilities;
public class MatchConditionDiscriminator : JsonConverter<MatchCondition>
{
    public override MatchCondition? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var readerClone = reader;

        if (readerClone.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException();
        }

        while (readerClone.Read())
        {
            if (readerClone.TokenType == JsonTokenType.PropertyName)
            {
                if (string.Equals(readerClone.GetString(), nameof(MatchCondition.MatchType), StringComparison.InvariantCultureIgnoreCase))
                {
                    readerClone.Read();
                    return readerClone.GetString() switch
                    {
                        nameof(ConditionMatchType.IPAddress) => JsonSerializer.Deserialize<IPAddressMatchCondition>(ref reader)!,
                        nameof(ConditionMatchType.Size) => JsonSerializer.Deserialize<SizeMatchCondition>(ref reader)!,
                        nameof(ConditionMatchType.String) => JsonSerializer.Deserialize<StringMatchCondition>(ref reader)!,
                        _ => throw new JsonException("MatchType is not recognised")
                    };
                }
            }
        }
        return null;
    }

    private static readonly MatchVariable[] _matchVariablesWithSelector = new[] { MatchVariable.Cookie, MatchVariable.RequestHeader, MatchVariable.PostArgs, MatchVariable.QueryParam };

    public override void Write(Utf8JsonWriter writer, MatchCondition value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        writer.WriteString(nameof(MatchCondition.MatchType), value.MatchType.ToString());
        writer.WriteBoolean(nameof(MatchCondition.Negate), value.Negate);

        if (value is TransformableMatchCondition transformable)
        {
            writer.WriteString(nameof(TransformableMatchCondition.MatchVariable), transformable.MatchVariable.ToString());

            if (_matchVariablesWithSelector.Contains((MatchVariable)transformable.MatchVariable!))
            {
                writer.WriteString(nameof(TransformableMatchCondition.Selector), transformable.Selector);
            }

            if (transformable is SizeMatchCondition sizeMatchCondition)
            {
                writer.WriteString(nameof(SizeMatchCondition.Operator), sizeMatchCondition.Operator.ToString());
                writer.WriteNumber(nameof(SizeMatchCondition.MatchValue), sizeMatchCondition.MatchValue);
            }
            else if (transformable is StringMatchCondition stringMatchCondition)
            {
                writer.WriteString(nameof(StringMatchCondition.Operator), stringMatchCondition.Operator.ToString());

                if (stringMatchCondition.MatchValues.Count > 0)
                {
                    writer.WritePropertyName(nameof(StringMatchCondition.MatchValues));
                    writer.WriteStartArray();
                    foreach (var item in stringMatchCondition.MatchValues)
                    {
                        writer.WriteStringValue(item);
                    }
                    writer.WriteEndArray();
                }
            }
            else
            {
                throw new JsonException("Type is not a known derived type of TransformableMatchCondition");
            }

            writer.WritePropertyName(nameof(TransformableMatchCondition.Transforms));
            writer.WriteStartArray();
            foreach (var item in transformable.Transforms)
            {
                writer.WriteStringValue(item.ToString());
            }
            writer.WriteEndArray();
        }
        else if (value is IPAddressMatchCondition ipMatchCondition)
        {
            writer.WriteString(nameof(IPAddressMatchCondition.MatchVariable), ipMatchCondition.MatchVariable.ToString());
            writer.WriteString(nameof(IPAddressMatchCondition.IPAddressOrRanges), ipMatchCondition.IPAddressOrRanges);
        }
        else
        {
            throw new JsonException("Type is not a known derived type of MatchCondition");
        }

        writer.WriteEndObject();
    }
}
