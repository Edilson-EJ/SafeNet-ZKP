using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet]
    [AllowAnonymous] // A sonda de disponibilidade não possui sessão.
    public IActionResult Get()
    {
        return Ok(new
        {
            status = "ok"
        });
    }
}
