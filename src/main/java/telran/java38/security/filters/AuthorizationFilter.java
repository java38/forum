package telran.java38.security.filters;

import java.io.IOException;

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
import telran.java38.user.dao.AccountRepository;

@Service
@Order(20)
public class AuthorizationFilter implements Filter {
	
	@Autowired
	AccountRepository accountRepository;
	
	@Autowired
	PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		System.out.println(request.getUserPrincipal().getName());
		//TODO
		chain.doFilter(request, response);

	}

}
