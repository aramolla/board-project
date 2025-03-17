# 게시판 관리 어플

- 인증으로는 JWT를 사용한다.


- 회원 등록  - POST /auth/signup
	- id, password, nickname 


- 회원 정보 조회 - GET /members


- 회원 정보 수정 - PUT /members
	- nickname 수정


- 회원 삭제 - DELETE /members
	- 삭제 시 회원이 등록한 게시물의 작성자는 (알 수 없음)으로 표현한다.


- 로그인 - POST /auth/login
	- 로그인 성공 시 AT,RT 발급.


- 게시물 등록 - POST /posts
	- 제목, 카테고리(하나만 들어), 작성자, 내용


- 게시물 조회 -
	- 상세 조회 - GET /posts/{postId}
		- 조회할려는 게시물의 ID로 조회한다.
	- 전체 조회  - GET /posts @RequestParam(required = false) String category
	- 카테고리 조회 - GET /posts + 쿼리 파라미터 
		- 특정 카테고리에 해당하는 게시물을 조회할 수 있다.	}


- 게시물 수정  PUT /posts/{postId}
	- 자신의 게시물만 수정 할 수 있다.
	- 제목과 내용을 수정 할 수 있다.


- 게시물 삭제  DELETE /posts/{postId}
	- 자신의 게시물만 삭제 할 수 있다.
