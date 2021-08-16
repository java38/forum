package telran.java38.security.filters;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

@Service
@Order(70)
public class CommentAuthorFilter implements Filter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		Principal principal = request.getUserPrincipal();
		if (principal != null && checkEndPoints(request.getServletPath(), request.getMethod())) {
			String path = request.getServletPath();
			String author = path.split("/")[5];
			if (!principal.getName().equals(author)){
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);

	}

	private boolean checkEndPoints(String path, String method) {
		return ("PUT".equalsIgnoreCase(method) && path.matches("[/]forum[/]post[/]\\w+[/]comment[/]\\w+[/]?"));
	}
}
