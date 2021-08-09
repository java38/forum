package telran.java38.security.filters;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java38.user.dao.AccountRepository;
import telran.java38.user.model.UserProfile;

@Service
@Order(10)
public class AuthenticationFilter implements Filter {

	@Autowired
	AccountRepository accountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoints(request.getServletPath(), request.getMethod())) {
			String auth = request.getHeader("Authorization");
			if (auth == null) {
				response.sendError(401, "Header Authorization is not exists");
				return;
			} else {
				try {
					int index = auth.indexOf(" ");
					auth = auth.substring(index + 1);
					byte[] bytesDecode = Base64.getDecoder().decode(auth);
					String token = new String(bytesDecode);
					String[] credentials = token.split(":");
					UserProfile userProfile = accountRepository.findById(credentials[0]).orElse(null);
					if (userProfile == null) {
						response.sendError(401, "Account not exists");
						return;
					}
					if (!BCrypt.checkpw(credentials[1], userProfile.getPassword())) {
						response.sendError(401, "User or password not valid");
						return;
					}
					request = new WrapperRequest(request, credentials[0]);
				} catch (Exception e) {
					response.sendError(401, "Header Authorization is not valid");
					return;
				}
			}
		}
		chain.doFilter(request, response);

	}

	private boolean checkEndPoints(String path, String method) {
		return !("POST".equalsIgnoreCase(method) && path.matches("[/]account[/]?"));
	}

	private class WrapperRequest extends HttpServletRequestWrapper {
		String user;

		public WrapperRequest(HttpServletRequest request, String user) {
			super(request);
			this.user = user;
		}
		
		@Override
		public Principal getUserPrincipal() {
			return new Principal() {
				
				@Override
				public String getName() {
					return user;
				}
			};
		}

	}

}
