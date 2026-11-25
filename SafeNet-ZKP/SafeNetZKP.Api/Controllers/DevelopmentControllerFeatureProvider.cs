using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace SafeNetZKP.Api.Controllers;

internal sealed class DevelopmentControllerFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
{
    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        feature.Controllers.Remove(typeof(CaptivePortalController).GetTypeInfo());
        feature.Controllers.Remove(typeof(GatewayObservationsController).GetTypeInfo());
    }
}
