using Jwt_Implementation.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;

namespace Jwt_Implementation
{
    public class ApplicationDbContext : DbContext
    {
        protected readonly IConfiguration Configuration;
        public ApplicationDbContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to sql server database
            options.UseMySql(Configuration.GetConnectionString("DefaultConnection"),
                mySqlOptionsAction: sqlOptions =>
                {
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 2,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null
                        );
                });
        }

        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

    }
}
