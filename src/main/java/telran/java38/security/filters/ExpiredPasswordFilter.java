package telran.java38.security.filters;

import java.io.IOException;
import java.security.Principal;
import java.time.LocalDate;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java38.user.dao.AccountRepository;
import telran.java38.user.model.UserProfile;

@Service
@Order(15)
public class ExpiredPasswordFilter implements Filter {

	@Autowired
	AccountRepository accountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		Principal principal = request.getUserPrincipal();
		if (principal != null && checkEndPoints(request.getServletPath(), request.getMethod())) {
			UserProfile userProfile = accountRepository.findById(principal.getName()).orElse(null);
			if (userProfile.getExpDate().isBefore(LocalDate.now())) {
				response.sendError(403, "password expired");
				return;
			}
		}

		chain.doFilter(request, response);

	}

	private boolean checkEndPoints(String path, String method) {
		return !("PUT".equalsIgnoreCase(method) && path.matches("[/]account[/]\\w+[/]password[/]?"));
	}

}
