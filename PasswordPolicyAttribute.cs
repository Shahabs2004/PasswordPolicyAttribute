using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.RegularExpressions;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false)]
public class PasswordPolicyAttribute : ValidationAttribute
{
    public int MinimumLength { get; set; } = 8;
    public int MaximumLength { get; set; } = 128;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireSpecialChar { get; set; } = true;
    public int MinimumSpecialChars { get; set; } = 1;
    public bool RequireDigit { get; set; } = true;
    public bool NoConsecutiveRepeatedChars { get; set; } = true;
    public bool NoSequentialChars { get; set; } = true;
    public bool NoDictionaryWords { get; set; } = true;
    public string ExcludedChars { get; set; } = "";
    public string ErrorSeparator { get; set; } = " ";

    // Basic dictionary of common words for simplicity; replace or expand for production use
    private static readonly HashSet<string> CommonWords = new HashSet<string>
    {
        "password", "123456", "qwerty", "abc123", "letmein", "welcome", "admin"
    };

    public PasswordPolicyAttribute(int minimumLength = 8, int maximumLength = 128, bool requireUppercase = true,
                                   bool requireLowercase = true, bool requireSpecialChar = true,
                                   int minimumSpecialChars = 1, bool requireDigit = true,
                                   bool noConsecutiveRepeatedChars = true, bool noSequentialChars = true,
                                   bool noDictionaryWords = true, string excludedChars = "", string errorSeparator = " ")
    {
        MinimumLength = minimumLength;
        MaximumLength = maximumLength;
        RequireUppercase = requireUppercase;
        RequireLowercase = requireLowercase;
        RequireSpecialChar = requireSpecialChar;
        MinimumSpecialChars = minimumSpecialChars;
        RequireDigit = requireDigit;
        NoConsecutiveRepeatedChars = noConsecutiveRepeatedChars;
        NoSequentialChars = noSequentialChars;
        NoDictionaryWords = noDictionaryWords;
        ExcludedChars = excludedChars;
        ErrorSeparator = errorSeparator;
    }

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        var password = value as string;
        var errorMessages = new List<string>();

        if (string.IsNullOrEmpty(password))
            errorMessages.Add("Password is required.");

        if (password.Length < MinimumLength)
            errorMessages.Add($"Password must be at least {MinimumLength} characters long.");

        if (password.Length > MaximumLength)
            errorMessages.Add($"Password must not exceed {MaximumLength} characters.");

        if (RequireUppercase && !password.Any(char.IsUpper))
            errorMessages.Add("Password must contain at least one uppercase letter.");

        if (RequireLowercase && !password.Any(char.IsLower))
            errorMessages.Add("Password must contain at least one lowercase letter.");

        if (RequireSpecialChar && password.Count(c => !char.IsLetterOrDigit(c)) < MinimumSpecialChars)
            errorMessages.Add($"Password must contain at least {MinimumSpecialChars} special character(s).");

        if (RequireDigit && !password.Any(char.IsDigit))
            errorMessages.Add("Password must contain at least one numeric digit.");

        if (NoConsecutiveRepeatedChars && HasConsecutiveRepeatedChars(password))
            errorMessages.Add("Password must not contain consecutive repeated characters.");

        if (NoSequentialChars && HasSequentialCharacters(password))
            errorMessages.Add("Password must not contain sequential characters.");

        if (NoDictionaryWords && ContainsDictionaryWord(password))
            errorMessages.Add("Password must not contain common dictionary words.");

        if (!string.IsNullOrEmpty(ExcludedChars) && password.Any(c => ExcludedChars.Contains(c)))
            errorMessages.Add($"Password must not contain any of the following characters: {ExcludedChars}");

        // Return all error messages if there are any errors, else return success
        if (errorMessages.Any())
            return new ValidationResult(string.Join(ErrorSeparator, errorMessages));

        return ValidationResult.Success;
    }

    private bool HasConsecutiveRepeatedChars(string password)
    {
        for (int i = 1; i < password.Length; i++)
        {
            if (password[i] == password[i - 1])
                return true;
        }
        return false;
    }

    private bool HasSequentialCharacters(string password)
    {
        // Check for ascending or descending sequences
        for (int i = 2; i < password.Length; i++)
        {
            if ((password[i] == password[i - 1] + 1 && password[i - 1] == password[i - 2] + 1) ||  // ascending
                (password[i] == password[i - 1] - 1 && password[i - 1] == password[i - 2] - 1))    // descending
            {
                return true;
            }
        }
        return false;
    }

    private bool ContainsDictionaryWord(string password)
    {
        var lowercasePassword = password.ToLower();
        return CommonWords.Any(word => lowercasePassword.Contains(word));
    }
}
