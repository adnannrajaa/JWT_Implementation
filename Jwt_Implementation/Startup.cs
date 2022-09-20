using Jwt_Implementation.Helper;
using Jwt_Implementation.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Jwt_Implementation
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
               .AddNewtonsoftJson(options =>
               options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
           );

            // configure strongly typed settings objects
            var appSettingsSection = Configuration.GetSection("AppSettings");
            services.Configure<AppSettings>(appSettingsSection);
            var appSettings = appSettingsSection.Get<AppSettings>();

            // configure jwt authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            }).AddJwtBearer(cfg =>
            {
                cfg.RequireHttpsMetadata = false;
                cfg.SaveToken = true;
                cfg.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = appSettings.JwtIssuer,
                    ValidAudience = appSettings.JwtAudience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appSettings.Secret)),
                    ClockSkew = TimeSpan.Zero // remove delay of token when expire
                };
                cfg.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context => {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });


            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<ClaimsPrincipal>(
               x =>
               {
                   var currentContext = x.GetService<IHttpContextAccessor>();
                   if (currentContext.HttpContext != null)
                   {
                       var claimsPrincipal = currentContext.HttpContext.User;
                       return claimsPrincipal;
                   }
                   else
                   {
                       return null;
                   }
               }
           );

            // configure Swagger
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Jwt_Implementation",
                    Version = "1",
                    Description = "Jwt_Implementation"
                });



                c.AddSecurityDefinition("Bearer",
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter into field the word 'Bearer' following by space and JWT",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },
                        Scheme = "oauth2",
                        Name = "Bearer",
                        In = ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                });

            });

            //Extract the requesting user information from the token
            services.AddScoped<ActiveUser>(
                x =>
                {
                    var currentContext = x.GetService<IHttpContextAccessor>();

                    if (currentContext != null && currentContext.HttpContext != null && currentContext.HttpContext.User != null)
                    {
                        var claimsPrincipal = currentContext.HttpContext.User;
                        ActiveUser ai = new ActiveUser();
                        ai.UserId = Convert.ToInt32(claimsPrincipal.Claims.Where(e => e.Type == "UserId").Select(e => e.Value).FirstOrDefault());
                        ai.UserName = claimsPrincipal.Claims.Where(e => e.Type == "UserName").Select(e => e.Value).FirstOrDefault();
                        ai.FirstName = claimsPrincipal.Claims.Where(e => e.Type == "FirstName").Select(e => e.Value).FirstOrDefault();
                        ai.LastName = claimsPrincipal.Claims.Where(e => e.Type == "LastName").Select(e => e.Value).FirstOrDefault();
                        return ai;
                    }
                    else
                    {
                        return null;
                    }
                }
            );

            services.AddHttpContextAccessor();
            services.AddDbContext<ApplicationDbContext>();
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IDapperService, DapperService>();
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                    builder.SetIsOriginAllowed(_ => true)
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials());
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ApplicationDbContext dataContext)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();

            // global cors policy
            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSwagger();
            app.UseSwaggerUI(opt =>
            {

                opt.SwaggerEndpoint("/swagger/v1/swagger.json", "Jwt_Implementation");

            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            // it will create database once application run. please make sure your connection string is correct. 
            dataContext.Database.Migrate();
        }
    }
}
