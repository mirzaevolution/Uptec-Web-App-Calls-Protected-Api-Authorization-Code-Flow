using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using UptecWebAppCallsProtectedApi.Models;

namespace UptecWebAppCallsProtectedApi.Controllers
{
    [Authorize]
    [AuthorizeForScopes(ScopeKeySection = "TodoApi:Scopes")]
    public class TodosController : Controller
    {
        private readonly IDownstreamApi _downstreamApi;
        private readonly IConfiguration _configuration;
        private readonly string _apiName = "TodoApi";
        private readonly string _relativePath;
        public TodosController(
                IDownstreamApi downstreamApi,
                IConfiguration configuration
            )
        {
            _downstreamApi = downstreamApi;
            _configuration = configuration;
            _relativePath = _configuration[$"{_apiName}:Path"]
                        ?? throw new Exception("Path configuration is empty/null");
        }

        public async Task<IActionResult> Index()
        {
            IEnumerable<TodoModel>? todos = await _downstreamApi
                .GetForUserAsync<IEnumerable<TodoModel>>(_apiName, options =>
                {
                    options.RelativePath = _relativePath;
                }
            );
            return View(todos);
        }

        public IActionResult Create() => View(default(CreateTodoViewModel));

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateTodoViewModel vm)
        {
            if (ModelState.IsValid)
            {
                await _downstreamApi
                    .PostForUserAsync<CreateTodoViewModel, TodoModel>(_apiName, vm,
                    options =>
                    {
                        options.RelativePath = _relativePath;
                    });
                return RedirectToAction(nameof(Index), "Todos");
            }
            return View(vm);
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            var todo = await _downstreamApi.GetForUserAsync<TodoModel>(_apiName,
                options =>
            {
                options.RelativePath = _relativePath + $"/{id}";

            });

            return View(todo != null ? new UpdateTodoViewModel
            {
                Id = todo.Id,
                Title = todo.Title,
                Description = todo.Description
            } : null);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(UpdateTodoViewModel vm)
        {

            if (ModelState.IsValid)
            {
                await _downstreamApi
                    .PutForUserAsync<UpdateTodoViewModel, TodoModel>(_apiName, vm,
                    options =>
                    {
                        options.RelativePath = _relativePath;
                    });
                return RedirectToAction(nameof(Index), "Todos");
            }
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _downstreamApi.CallApiForUserAsync(_apiName, options =>
            {
                options.RelativePath = _relativePath + $"/{id}";
                options.HttpMethod = HttpMethods.Delete;
            });

            return RedirectToAction(nameof(Index), "Todos");

        }

    }
}
