<br><br>
# .*Security*

<br>
<br>
<br>
<br>

### 권한  -Authorization  
 '자신을 증명하는 것'

<br><br>

### 인증 - Authentication
'스스로 무엇인가 증명할 만한 자료를 제시하는 것'

<br>
<br>

------------------------------
<br>

가장 중요-? _ **Authentication Manager** (인증 매니저) <br>
#### 인증 구조 설계 

<br><br>

![화면 캡처 2024-12-30 122645](https://github.com/user-attachments/assets/1623b847-32e8-4ee9-a688-24b5b6b235f1)


<br><br>


![화면 캡처 2024-12-30 122738](https://github.com/user-attachments/assets/d39d2f53-e56a-4cf1-92c2-16dc0595721e)

<br>

#### usedetail 원하는 서류 customizing
사용자가 원하는 정보를 처리해서 반환 하기 위해 필요로 한다.


root 와 나란히 폴더를 만들어준다..!

#### security-context.xml 

      
      <?xml version="1.0" encoding="UTF-8"?>
      <beans xmlns="http://www.springframework.org/schema/beans"
      	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      	xmlns:security="http://www.springframework.org/schema/security"
      	xsi:schemaLocation="http://www.springframework.org/schema/security
      	 http://www.springframework.org/schema/security/spring-security.xsd
      	 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
      	
      	
      <security:http>
      		<security:intercept-url pattern="/sample/all" access="permitAll"/>
      		
      		<security:intercept-url pattern="/sample/member"
      		access="hasRole('ROLE_MEMBER')"/>
      	
      		
      		<security:form-login />
      	</security:http>
      
      	<security:authentication-manager>
      		
      	</security:authentication-manager>
      </beans>
      

<br>
<br>

#### access = "permitAll": 아무나 
#### access ="hasRole('Role_Member') : 멤버만

<br>
<br>

sample/member 로 실행 시  아래와 같은 창이 뜸..!!

![화면 캡처 2024-12-30 123650](https://github.com/user-attachments/assets/a9d52a84-9e81-4299-9c3b-71e63758aedc)


++

      <security:authentication-manager>
      		<security:authentication-provider>
      			<security:user-service>
      				<security:user name="member" password="member" authorities="ROLE_MEMBER"/>
      			</security:user-service>
      		</security:authentication-provider>
      	</security:authentication-manager>


### ERROR 
암호화 되지 않은 password 
PasswordEncoder$UnmappedIdPasswordEncoder.matches


* 스프링은 암호화 패스하는 코드를 치면 넘어간다.
{noop} - password 없이 사용하겠다.,

* BOOT 는 가상 암호를 줌.


![화면 캡처 2024-12-30 124835](https://github.com/user-attachments/assets/7b8c6efc-7d1c-4853-aa36-19375541c8fc)

<br>
<br>

그래도 안된다면 
![화면 캡처 2024-12-30 125104](https://github.com/user-attachments/assets/800d2d08-4de3-4c91-8b05-0572e9f55c8b)

login Cookies를 delete해야 실행된다. 
<br>
아래에 추가로 admin
#### <security:user name="admin" password="{noop}admin" authorities="ROLE_MEMBER, ROLE_ADMIN"/> 맴버와 관리자가 둘 다 가능하게..!
#### BOOT 에서는 상위 설정에서 전체를 관리자가 관리하게 설정 가능하다.

<br>
<br>

### ERRROR 페이지 대체
      
      <?xml version="1.0" encoding="UTF-8"?>
      <beans xmlns="http://www.springframework.org/schema/beans"
      	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      	xmlns:security="http://www.springframework.org/schema/security"
      	xsi:schemaLocation="http://www.springframework.org/schema/security
      	 http://www.springframework.org/schema/security/spring-security.xsd
      	 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
      
      
      <bean id= "customAccessDenied" class="com.company.security.CustomAccessDeniedHandler"></bean>
      	<security:http>
      		<security:intercept-url pattern="/sample/all" access="permitAll"/>
      		
      		<security:intercept-url pattern="/sample/member"
      			access="hasRole('ROLE_MEMBER')"/>
      		
      		<security:intercept-url pattern="/sample/admin"
      			access="hasRole('ROLE_ADMIN')"/>
      			<!-- <security:access-denied-handler error-page="/acessError" /> -->
      		<security:access-denied-handler ref="customAccessDenied" />
      		
      		<security:form-login />
      		
      	</security:http>
      	
      
      	<security:authentication-manager>
      		<security:authentication-provider>
      			<security:user-service>
      				<security:user name="member" password="{noop}member" authorities="ROLE_MEMBER"/>
      				<security:user name="admin" password="{noop}admin" authorities="ROLE_MEMBER, ROLE_ADMIN"/>
      				
      				
      			</security:user-service>
      		</security:authentication-provider>
      	</security:authentication-manager>
      </beans>
      


![화면 캡처 2024-12-30 142817](https://github.com/user-attachments/assets/41d22631-ef57-495f-8539-aba1b5caaf3f)




<br>
<br>


costomLogin.jsp 
      
      <body>
      	<h1>Custom Login Page</h1>
      	<h2><c:out value="${error}"/></h2>
      	<h2><c:out value="${logout}"/></h2>
      	
      	<form method="post" action="/login">
      		<div>
      			<input type='text' name='username' value='admin'>
      		</div>
      		<div>
      			<input type='password' name='password' value='admin'>
      		</div>
      		<div>
      			<input type='submit' >
      		</div>
      		<input type ="hidden" name="${_csrf.parmeterName}" value="${_csrf.token}" />
      
      	</form>
      
      </body>


### CSRF 란? 사이트 간 위조 방지 목적으로 특정한 값의 토큰을 사용하는 방식이다. ' 위조방지 ' 활성화시 사용할때 마다 값이 바뀐다. 

![화면 캡처 2024-12-30 144916](https://github.com/user-attachments/assets/2e2812ca-d337-4b9f-ac48-4f67b27a280e)


<br>
<br>


* 안보이게 처리하려면?? 
 security-context.xml
![화면 캡처 2024-12-30 145247](https://github.com/user-attachments/assets/dcaad2a3-8093-4cb2-b577-d72cc049a667)

<br>


![화면 캡처 2024-12-30 145355](https://github.com/user-attachments/assets/dfe485d5-9053-4d3c-94e2-121cbc874445)

csrf 의 value 는 보이지 않아야 한다.


<br>

<br>

### 어떤 사이트에 가던지 admin 으로 로그인하면 admin 사이트로 (특정) 사이트 지정하기 

#### CustomLoginSuccessHandler
.jsp

<br>

      package com.company.security;
      
      
      @Log4j
      public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler{
      
      	@Override
      	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      			Authentication auth) throws IOException, ServletException {
      		
      		log.warn("Login Success");
      		
      		List<String> roleNames = new ArrayList<>();
      		
      		auth.getAuthorities().forEach(authority -> {
      			
      			roleNames.add(authority.getAuthority());
      		});
      		
      		log.warn("ROLE NAMES: "+roleNames);
      		
      		if (roleNames.contains("ROLE_ADMIN")) {
      			
      			response.sendRedirect("/sample/admin");
      			return;
      		}
      		if (roleNames.contains("ROLE_MEMBER")) {
      			
      			response.sendRedirect("/sample/member");
      			return;
      		}
      		
      		response.sendRedirect("/");
      	}
      
      }
      
<br>


![화면 캡처 2024-12-30 164321](https://github.com/user-attachments/assets/29453674-90cf-4bc0-821a-2eacee6ef06e)
![화면 캡처 2024-12-30 164341](https://github.com/user-attachments/assets/bb93f64a-356f-45cd-9bd2-c57c27ba7e7c)

<br>

![화면 캡처 2024-12-30 163818](https://github.com/user-attachments/assets/7cd736c5-93f9-462a-bfae-505b58db7ddf)



      
<br>
<br>


![화면 캡처 2024-12-30 152457](https://github.com/user-attachments/assets/ad130ca4-7b1a-46dc-8007-a543e1ba69d9)

<br>


![화면 캡처 2024-12-30 164417](https://github.com/user-attachments/assets/89e158ec-8b9f-476a-90f4-a88969035f13)

<br>



customLogin.jsp
<br>

      
      <%@ page language="java" contentType="text/html; charset=UTF-8"
          pageEncoding="UTF-8"%>
      <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>    
      <!DOCTYPE html>
      <html>
      <head>
      <meta charset="UTF-8">
      <title>Insert title here</title>
      </head>
      <body>
      	<h1>Custom Login Page</h1>
      	<h2><c:out value="${error}"/></h2>
      	<h2><c:out value="${logout}"/></h2>
      	
      	<form method="post" action="/login">
      		<div>
      			<input type='text' name='username'  value='admin'>
      		</div>
      		<div>
      			<input type='password' name='password' value='admin'>
      		</div>
      		<div>
      			<input type='submit' >
      		</div>
      		<input type ="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
      
      	</form>
      
      </body>
      </html>

<br>
<br>


customLogout.jsp

<br>
      
      <%@ page language="java" contentType="text/html; charset=UTF-8"
          pageEncoding="UTF-8"%>
      <!DOCTYPE html>
      <html>
      <head>
      <meta charset="UTF-8">
      <title>Insert title here</title>
      </head>
      <body>
      <h1> Logout Page</h1>
      
      <form action="/customLogout" method='post'>
      <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
      <button>로그아웃</button>
      </form>
      
      </body>
      </html>


<br>

![화면 캡처 2024-12-30 164543](https://github.com/user-attachments/assets/6c25ac1f-8316-47f4-89ad-99ba47e77c29)

<br>

![화면 캡처 2024-12-30 162839](https://github.com/user-attachments/assets/a5267ea3-6c7e-438d-a085-82abc489126b)

<br>

>로그아웃 실행 후 화면

![화면 캡처 2024-12-30 162928](https://github.com/user-attachments/assets/a0aff282-3d43-487a-9b4b-aab2c54ecfd3)
<br>

>로그아웃 버튼을 누르고 나면 

![화면 캡처 2024-12-30 162814](https://github.com/user-attachments/assets/df26c4a5-9b91-4e75-80f2-2754041b6ad5)
>redirect

<br>
<br>

![화면 캡처 2024-12-30 164624](https://github.com/user-attachments/assets/a75f68db-97e2-4b0a-9823-34790899c60a)

위와 같은 시나리오로 작동하게 된다...! 
