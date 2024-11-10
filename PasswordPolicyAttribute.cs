using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false)]
public class PasswordPolicyAttribute : ValidationAttribute
{
    public class PolicyOptions
    {
        public int MinimumLength { get; set; } = 12;  // Increased from 8 for better security
        public int MaximumLength { get; set; } = 128;
        public bool RequireUppercase { get; set; } = true;
        public bool RequireLowercase { get; set; } = true;
        public bool RequireSpecialChar { get; set; } = true;
        public int MinimumSpecialChars { get; set; } = 1;
        public bool RequireDigit { get; set; } = true;
        public int MinimumDigits { get; set; } = 1;
        public bool NoConsecutiveRepeatedChars { get; set; } = true;
        public int MaxConsecutiveRepeats { get; set; } = 2;
        public bool NoSequentialChars { get; set; } = true;
        public bool NoDictionaryWords { get; set; } = true;
        public string ExcludedChars { get; set; } = "";
        public string ErrorSeparator { get; set; } = " ";
        public int MinimumUniqueChars { get; set; } = 8;
        public double MinimumEntropy { get; set; } = 50.0; // Minimum password entropy in bits
    }

    private readonly PolicyOptions _options;
    private static readonly Lazy<HashSet<string>> CommonWords = new Lazy<HashSet<string>>(LoadCommonWords);

    public PasswordPolicyAttribute()
    {
        _options = new PolicyOptions();
    }

    public PasswordPolicyAttribute(PolicyOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is not string password)
        {
            return new ValidationResult("Password must be a string value.");
        }

        var validationResults = ValidatePassword(password).ToList();

        return validationResults.Any()
            ? new ValidationResult(string.Join(_options.ErrorSeparator, validationResults))
            : ValidationResult.Success;
    }

    private IEnumerable<string> ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            yield return "Password is required.";
            yield break;
        }

        var validationRules = new List<(Func<string, bool> Rule, string ErrorMessage)>
        {
            (p => p.Length >= _options.MinimumLength, 
             $"Password must be at least {_options.MinimumLength} characters long."),
            
            (p => p.Length <= _options.MaximumLength, 
             $"Password must not exceed {_options.MaximumLength} characters."),
            
            (p => !_options.RequireUppercase || p.Any(char.IsUpper), 
             "Password must contain at least one uppercase letter."),
            
            (p => !_options.RequireLowercase || p.Any(char.IsLower), 
             "Password must contain at least one lowercase letter."),
            
            (p => !_options.RequireSpecialChar || p.Count(c => !char.IsLetterOrDigit(c)) >= _options.MinimumSpecialChars,
             $"Password must contain at least {_options.MinimumSpecialChars} special character(s)."),
            
            (p => !_options.RequireDigit || p.Count(char.IsDigit) >= _options.MinimumDigits,
             $"Password must contain at least {_options.MinimumDigits} numeric digit(s)."),
            
            (p => !_options.NoConsecutiveRepeatedChars || !HasConsecutiveRepeatedChars(p),
             $"Password must not contain more than {_options.MaxConsecutiveRepeats} consecutive repeated characters."),
            
            (p => !_options.NoSequentialChars || !HasSequentialCharacters(p),
             "Password must not contain sequential characters."),
            
            (p => !_options.NoDictionaryWords || !ContainsDictionaryWord(p),
             "Password must not contain common dictionary words."),
            
            (p => string.IsNullOrEmpty(_options.ExcludedChars) || !p.Any(c => _options.ExcludedChars.Contains(c)),
             $"Password must not contain any of the following characters: {_options.ExcludedChars}"),
            
            (p => p.Distinct().Count() >= _options.MinimumUniqueChars,
             $"Password must contain at least {_options.MinimumUniqueChars} unique characters."),
            
            (p => CalculatePasswordEntropy(p) >= _options.MinimumEntropy,
             $"Password is not complex enough. Please use a more varied combination of characters.")
        };

        foreach (var (rule, errorMessage) in validationRules)
        {
            if (!rule(password))
            {
                yield return errorMessage;
            }
        }
    }

    private bool HasConsecutiveRepeatedChars(string password)
    {
        int consecutiveCount = 1;
        for (int i = 1; i < password.Length; i++)
        {
            if (password[i] == password[i - 1])
            {
                consecutiveCount++;
                if (consecutiveCount > _options.MaxConsecutiveRepeats)
                    return true;
            }
            else
            {
                consecutiveCount = 1;
            }
        }
        return false;
    }

    private bool HasSequentialCharacters(string password)
    {
        string[] commonSequences = { "abcdefghijklmnopqrstuvwxyz", "0123456789" };
        var lowercasePassword = password.ToLower();

        foreach (var sequence in commonSequences)
        {
            for (int i = 0; i < sequence.Length - 2; i++)
            {
                var pattern = sequence.Substring(i, 3);
                if (lowercasePassword.Contains(pattern) || 
                    lowercasePassword.Contains(new string(pattern.Reverse().ToArray())))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private bool ContainsDictionaryWord(string password)
    {
        var lowercasePassword = password.ToLower();
        return CommonWords.Value.Any(word => 
            word.Length >= 4 && lowercasePassword.Contains(word));
    }

    private static HashSet<string> LoadCommonWords()
    {
        // In a real implementation, load from a file or database
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "password", "123456", "qwerty", "abc123", "letmein", "welcome", "admin",
            "monkey", "dragon", "baseball", "football", "master", "hello", "shadow"
            // Add more common words as needed
        };
    }

    private double CalculatePasswordEntropy(string password)
    {
        var charSetSize = 0;
        if (password.Any(char.IsLower)) charSetSize += 26;
        if (password.Any(char.IsUpper)) charSetSize += 26;
        if (password.Any(char.IsDigit)) charSetSize += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) charSetSize += 32;

        return password.Length * Math.Log2(charSetSize);
    }
}

// Example usage:
public class UserAccount
{
    public string Username { get; set; }

    [PasswordPolicy]
    public string Password { get; set; }

    // Or with custom options:
    /*
    [PasswordPolicy(new PolicyOptions 
    {
        MinimumLength = 14,
        MinimumSpecialChars = 2,
        MinimumDigits = 2,
        MinimumUniqueChars = 10,
        MinimumEntropy = 60.0
    })]
    public string Password { get; set; }
    */
}