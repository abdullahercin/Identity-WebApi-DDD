using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using Assist.Identity.Application.Models;

namespace Assist.Identity.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BaseController : ControllerBase
    {
        [NonAction]
        public IActionResult CreateActionResult<T>(ServiceResult<T> result)
        {
            return result.Status switch
            {
                HttpStatusCode.NoContent => NoContent(),
                HttpStatusCode.Created => Created(result.UrlAsCreated, result),
                HttpStatusCode.OK => Ok(result.Data),
                HttpStatusCode.NotFound => NotFound(null),
                _ => new ObjectResult(result.ProblemDetails) { StatusCode = result.Status.GetHashCode() }
            };
        }

        [NonAction]
        public IActionResult CreateActionResult(ServiceResult result)
        {
            return result.Status switch
            {
                HttpStatusCode.NoContent => new ObjectResult(null) { StatusCode = result.Status.GetHashCode() },
                HttpStatusCode.NotFound => NotFound(null),
                _ => new ObjectResult(result.ProblemDetails) { StatusCode = result.Status.GetHashCode() }
            };
        }
    }
}
