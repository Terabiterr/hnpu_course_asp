using Microsoft.EntityFrameworkCore;
using shop_app.Models;

namespace shop_app.Services
{
    public interface IServiceProduct
    {
        Task<Product?> CreateAsync(Product? product);
        Task<IEnumerable<Product>> ReadAsync();
        Task<Product?> GetByIdAsync(int id);
        Task<Product?> UpdateAsync(int id, Product? product);
        Task<bool> DeleteAsync(int id);
    }
    public class ServiceProduct : IServiceProduct
    {
        private readonly ProductContext _productContext;
        private readonly ILogger<ServiceProduct> _logger;
        public ServiceProduct(
            ProductContext productContext, 
            ILogger<ServiceProduct> logger)
        {
            _productContext = productContext;
            _logger = logger;
        }

        public async Task<Product?> CreateAsync(Product? product)
        {
            if(product == null)
            {
                _logger.LogWarning("Attempt created a product with null");
                return null;
            }
            await _productContext.AddAsync(product);
            await _productContext.SaveChangesAsync();
            return product;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var product = await _productContext.Products.FindAsync(id);
            if(product == null)
            {
                return false;
            }
            _productContext.Products.Remove(product);
            await _productContext.SaveChangesAsync();
            return true;
        }

        public async Task<Product?> GetByIdAsync(int id)
        {
            return await _productContext.Products.FindAsync(id);
        }

        public async Task<IEnumerable<Product>> ReadAsync()
        {
            return await _productContext.Products.ToListAsync();
        }

        public async Task<Product?> UpdateAsync(int id, Product? product)
        {
            if (product == null || id != product.Id)
            {
                _logger.LogWarning($"{nameof(Product)}: {id}");
                return null;
            }
            try
            {
                _productContext.Products.Update(product);
                await _productContext.SaveChangesAsync();
                return product;
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex.Message);
                return null;
            }
        }
    }
}
