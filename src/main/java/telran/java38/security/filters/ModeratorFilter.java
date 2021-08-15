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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.java38.forum.dao.PostRepository;
import telran.java38.forum.model.Post;
import telran.java38.user.dao.AccountRepository;
import telran.java38.user.model.UserProfile;

@Service
@Order(30)
public class ModeratorFilter implements Filter{
	
	@Autowired
	AccountRepository accountRepository;

	@Autowired
	PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		Principal principal = request.getUserPrincipal();
		if (principal != null && checkEndPoints(request.getServletPath(), request.getMethod())) {
			String path = request.getServletPath();
			String postId = path.split("/")[3];
			Post post = postRepository.findById(postId).orElse(null);
			if (post == null) {
				response.sendError(404, "Post not found");
				return;
			}
			UserProfile userProfile = accountRepository.findById(principal.getName()).orElse(null);
			if (!(principal.getName().equals(post.getAuthor())
					|| userProfile.getRoles().contains("Moderator"))){
				response.sendError(403);
				return;
			}
		}

		chain.doFilter(request, response);

	}

	private boolean checkEndPoints(String path, String method) {
		return ("PUT".equalsIgnoreCase(method) && path.matches("[/]forum[/]post[/]\\w+[/]?")
				|| "DELETE".equalsIgnoreCase(method) && path.matches("[/]forum[/]post[/]\\w+[/]?"));
	}


}
