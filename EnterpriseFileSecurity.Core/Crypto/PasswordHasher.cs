using System;
using System.Security.Cryptography;

namespace EnterpriseFileSecurity.Core.Crypto;

public static class PasswordHasher
{
    private const int DefaultIterations = 100000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static (byte[] hash, byte[] salt, int iterations) HashPassword(string password)
    {
        byte[] salt = GenerateSalt(SaltSize);
        int iterations = DefaultIterations;
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        byte[] hash = pbkdf2.GetBytes(HashSize);
        return (hash, salt, iterations);
    }

    public static bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, storedSalt, iterations, HashAlgorithmName.SHA256);
        byte[] computedHash = pbkdf2.GetBytes(HashSize);
        return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
    }

    public static byte[] DeriveKEK(string password, byte[] keySalt, int iterations = DefaultIterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, keySalt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    private static byte[] GenerateSalt(int size)
    {
        byte[] salt = new byte[size];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }
}
