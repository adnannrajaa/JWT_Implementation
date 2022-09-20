using Dapper;
using Microsoft.EntityFrameworkCore;
using System;
using System.Data;
using System.Threading.Tasks;

namespace Jwt_Implementation.Services
{
    public interface IDapperService : IDisposable
    {
        Task<bool> ExecuteAsync(string RawQuery, DynamicParameters param = null);
        Task<T> ReturnRowAsync<T>(string RawQuery, DynamicParameters param = null);
    }
    public class DapperService : IDapperService
    {
        private readonly ApplicationDbContext _context;
        public DapperService(ApplicationDbContext context)
        {
            _context = context;
        }
        public async Task<bool> ExecuteAsync(string RawQuery, DynamicParameters param = null)
        {
            var _db = _context.Database.GetDbConnection();
            var result  = await _db.ExecuteAsync(RawQuery, param, commandType: CommandType.Text);
            return result > 0 ? true : false;
        }
        public async Task<T> ReturnRowAsync<T>(string RawQuery, DynamicParameters param = null)
        {
            var _db = _context.Database.GetDbConnection();
            return await _db.QueryFirstOrDefaultAsync<T>(RawQuery, param, commandType: CommandType.Text);
        }
        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
