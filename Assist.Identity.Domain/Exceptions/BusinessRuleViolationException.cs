namespace Assist.Identity.Domain.Exceptions;

/// <summary>
/// Business Rule Violation Exception
/// Genel business rule ihlallerinde kullanılır
/// Specific exception olmadığında fallback olarak kullanılabilir
/// </summary>
public class BusinessRuleViolationException : DomainException
{
    /// <summary>
    /// BusinessRuleViolationException constructor
    /// </summary>
    /// <param name="ruleName">İhlal edilen rule'ün adı</param>
    /// <param name="ruleDescription">Rule açıklaması</param>
    public BusinessRuleViolationException(string ruleName, string ruleDescription) 
        : base($"Business rule violation: {ruleName}. {ruleDescription}")
    {
        RuleName = ruleName;
        RuleDescription = ruleDescription;
    }

    /// <summary>
    /// BusinessRuleViolationException constructor with entity context
    /// </summary>
    /// <param name="ruleName">İhlal edilen rule'ün adı</param>
    /// <param name="ruleDescription">Rule açıklaması</param>
    /// <param name="entityType">Entity type</param>
    /// <param name="entityId">Entity ID</param>
    public BusinessRuleViolationException(string ruleName, string ruleDescription, string entityType, Guid entityId) 
        : base($"Business rule violation in {entityType} ({entityId}): {ruleName}. {ruleDescription}")
    {
        RuleName = ruleName;
        RuleDescription = ruleDescription;
        EntityType = entityType;
        EntityId = entityId;
    }

    /// <summary>
    /// İhlal edilen rule'ün adı
    /// </summary>
    public string RuleName { get; }

    /// <summary>
    /// Rule açıklaması
    /// </summary>
    public string RuleDescription { get; }

    /// <summary>
    /// Entity type (User, Role vs.)
    /// </summary>
    public string EntityType { get; }

    /// <summary>
    /// Entity ID
    /// </summary>
    public Guid? EntityId { get; }

    /// <summary>
    /// Exception kategorisi
    /// </summary>
    public override string Category => "BusinessRule";

    /// <summary>
    /// Error code
    /// </summary>
    public override string ErrorCode => "BUSINESS_RULE_VIOLATION";
}