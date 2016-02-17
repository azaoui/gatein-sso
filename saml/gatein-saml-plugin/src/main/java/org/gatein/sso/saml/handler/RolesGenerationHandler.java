package org.gatein.sso.saml.handler;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.services.organization.Membership;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.security.MembershipEntry;
import org.exoplatform.services.security.RolesExtractor;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.handlers.saml2.BaseSAML2Handler;

/**
 * Handles the generation of roles on the SP Side
 */
public class RolesGenerationHandler extends BaseSAML2Handler {

	public void handleStatusResponseType(SAML2HandlerRequest request,
			SAML2HandlerResponse response) throws ProcessingException {
		// Do not handle log out request interaction
		if (request.getSAML2Object() instanceof LogoutRequestType)
			return;

		// only handle SP side
		if (getType() == HANDLER_TYPE.IDP)
			return;

		extractUserRolesInResponse(request, response);
	}

	@Override
	public void handleRequestType(SAML2HandlerRequest request,
			SAML2HandlerResponse response) throws ProcessingException {
		// Do not handle log out request interaction
		if (request.getSAML2Object() instanceof LogoutRequestType)
			return;

		// only handle IDP side
		if (getType() == HANDLER_TYPE.SP)
			return;

		extractUserRolesInResponse(request, response);
	}

	private void extractUserRolesInResponse(SAML2HandlerRequest request,
			SAML2HandlerResponse response) {
		HTTPContext httpContext = (HTTPContext) request.getContext();
		HttpSession session = httpContext.getRequest().getSession(false);

		String userId = httpContext.getRequest().getRemoteUser();
		if (userId == null) {
			Principal principal = httpContext.getRequest().getUserPrincipal();
			if (principal == null) {
				principal = (Principal) session
						.getAttribute(GeneralConstants.PRINCIPAL_ID);

				if (principal == null) {
					throw new IllegalStateException("User not found in request");
				}
			}
			userId = principal.getName();
		}

		OrganizationService organizationService = (OrganizationService) PortalContainer
				.getInstance().getComponentInstanceOfType(
						OrganizationService.class);
		RolesExtractor rolesExtractor = (RolesExtractor) PortalContainer
				.getInstance().getComponentInstanceOfType(RolesExtractor.class);

		Collection<Membership> memberships = null;
		try {
			memberships = organizationService.getMembershipHandler()
					.findMembershipsByUser(userId);
		} catch (Exception e) {
			throw new IllegalStateException(
					"Error occured while retrieving list of memberships of user "
							+ userId, e);
		}
		if (memberships == null) {
			logger.warn("User '" + userId + "' does not have memberships");
			return;
		}
		Set<MembershipEntry> entries = new HashSet<MembershipEntry>();
		for (Membership membership : memberships)
			entries.add(new MembershipEntry(membership.getGroupId(), membership
					.getMembershipType()));

		List<String> roles = new ArrayList<String>(rolesExtractor.extractRoles(
				userId, entries));
		session.setAttribute(GeneralConstants.ROLES_ID, roles);
		response.setRoles(roles);
	}
}