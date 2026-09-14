<?php

declare(strict_types=1);

namespace ShieldCI\Analyzers\Reliability;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Support\Collection;
use ShieldCI\AnalyzersCore\Abstracts\AbstractFileAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\Category;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\ValueObjects\AnalyzerMetadata;
use ShieldCI\AnalyzersCore\ValueObjects\Location;
use ShieldCI\Concerns\ParsesPHPStanResults;
use ShieldCI\Support\PHPStanRunner;

/**
 * Consolidated PHPStan analyzer that replaces 13 separate analyzers.
 *
 * This analyzer runs PHPStan once and categorizes issues into:
 * - Dead Code
 * - Deprecated Code
 * - Invalid Method Calls
 * - Invalid Function Calls
 * - Invalid Property Access
 * - Invalid Offsets
 * - Undefined Variables
 * - Undefined Constants
 * - Missing Return Statements
 * - Invalid Imports
 * - Invalid Method Overrides
 * - Foreach Iterable Issues
 * - Missing Model Relations
 *
 * Every error is assigned to exactly one category. Anything that matches no
 * category lands in "Other PHPStan Issues" rather than being discarded.
 *
 * Configuration allows enabling/disabling specific categories.
 *
 * @phpstan-import-type PHPStanIssue from PHPStanRunner
 */
class PHPStanAnalyzer extends AbstractFileAnalyzer
{
    use ParsesPHPStanResults;

    /**
     * Category key used for errors that match nothing else.
     */
    private const OTHER_CATEGORY = 'other';

    /**
     * Number of analysis errors quoted in a result message before summarising the rest.
     */
    private const MAX_ANALYSIS_ERRORS_IN_MESSAGE = 3;

    /**
     * All issue categories with their patterns and severity levels.
     *
     * Declaration order is LOAD-BEARING: categoryFromMessage() evaluates these in
     * order and takes the first pattern match, which is what makes classification
     * single-assignment instead of the fan-out it used to be. Reordering changes
     * which category an overlapping message lands in. self::OTHER_CATEGORY must
     * stay last and must stay pattern-less - it is reached by explicit assignment,
     * never by matching.
     *
     * @var array<string, array{severity: Severity, patterns: array<string>, regex?: string, name: string, description: string}>
     */
    private const ISSUE_CATEGORIES = [
        'dead-code' => [
            'name' => 'Dead Code',
            'description' => 'Unreachable code, unused variables, and statements with no effect',
            'severity' => Severity::Medium,
            'patterns' => [
                '*does not do anything*',
                'Unreachable statement*',
                '* is unused*',
                'Empty array passed*',
                'Dead catch*',
                '*has no effect*',
                '*will never be executed*',
                'Left side of && is always *',
                'Left side of || is always *',
                'Right side of && is always *',
                'Right side of || is always *',
                'Result of && is always *',
                'Result of || is always *',
                'Negated boolean expression is always *',
                'Strict comparison using * will always evaluate to *',
                'Comparison operation * between * and * is always *',
            ],
        ],

        'deprecated-code' => [
            'name' => 'Deprecated Code',
            'description' => 'Usage of deprecated methods, classes, and functions',
            'severity' => Severity::High,
            // Anchored to PHPStan's actual deprecation wording. A bare "deprecated"
            // substring test also claims errors about symbols that merely have
            // "Deprecated" in their name, which under single assignment would steal
            // them from the category that should own them.
            'regex' => '#(?:^(?:Call to|Usage of|Access to|Fetching|Instantiation of) deprecated\b)|(?:\bis deprecated\b)#i',
            'patterns' => [],
        ],

        'foreach-iterable' => [
            'name' => 'Foreach Iterable Issues',
            'description' => 'Invalid foreach usage with non-iterable values',
            'severity' => Severity::High,
            'patterns' => [
                'Argument of an invalid type * supplied for foreach*',
                'Cannot use * in a foreach loop*',
                'Iterating over * but * does not specify*',
            ],
        ],

        'invalid-function-calls' => [
            'name' => 'Invalid Function Calls',
            'description' => 'Calls to undefined functions or invalid function parameters',
            'severity' => Severity::High,
            'patterns' => [
                'Function * not found*',
                'Function * invoked with * parameter*',
                'Parameter * of function * expects*',
                'Missing parameter * in call to function *',
                'Unknown parameter * in call to function *',
                'Result of function * (void) is used*',
                'Cannot call function * on *',
            ],
        ],

        'invalid-imports' => [
            'name' => 'Invalid Imports',
            'description' => 'Usage of non-existent classes, interfaces, or traits',
            'severity' => Severity::Critical,
            'patterns' => [
                'Used * not found*',
                'Class * not found*',
                'Interface * not found*',
                'Trait * not found*',
                'Instantiated class * not found*',
                'Reflection class * does not exist*',
            ],
        ],

        'invalid-method-calls' => [
            'name' => 'Invalid Method Calls',
            'description' => 'Calls to undefined methods or invalid method parameters',
            'severity' => Severity::Critical,
            'patterns' => [
                'Method * invoked with *',
                'Parameter * of method * is passed by reference, so *',
                'Unable to resolve the template *',
                'Missing parameter * in call to *',
                'Unknown parameter * in call to *',
                'Call to method * on an unknown class *',
                'Cannot call method * on *',
                'Call to private method * of parent class *',
                'Call to an undefined method *',
                'Call to * method * of class *',
                'Call to an undefined static method *',
                'Static call to instance method *',
                'Calling *::* outside of class scope*',
                '*::* calls parent::* but *',
                'Call to static method * on an unknown class *',
                'Cannot call static method * on *',
                'Cannot call abstract* method *::*',
                '* invoked with * parameter* required*',
                'Parameter * of * expects * given*',
                'Result of * (void) is used*',
                'Result of method *',
            ],
        ],

        'invalid-method-overrides' => [
            'name' => 'Invalid Method Overrides',
            'description' => 'Incompatible method overrides in child classes',
            'severity' => Severity::High,
            'patterns' => [
                'Return type * of method *::* is not covariant with*',
                'Parameter * of method *::* is not contravariant with*',
                'Method *::* overrides method *::* but is missing parameter *',
                'Method *::* has parameter * with no type*',
                'Overridden method *::* is deprecated*',
                'Method *::* with return type * returns * but should return *',
                'Method *::* extends method *::* but changes visibility from *',
                'Method *::* overrides *::* with different parameter *',
                'Method *::* is not compatible with *::*',
                'Method *::* never returns * so it can be removed from*',
            ],
        ],

        'invalid-offset-access' => [
            'name' => 'Invalid Offset Access',
            'description' => 'Invalid array or object offset access',
            'severity' => Severity::High,
            'patterns' => [
                'Cannot assign * offset * to *',
                'Cannot access offset * on *',
                'Offset * does not exist on *',
                'Offset * might not exist on *',
                'Offset * on * always exists*',
                'Cannot unset offset * on *',
                'Offset * on * does not accept type *',
                'Offset string on * in isset*',
            ],
        ],

        'invalid-property-access' => [
            'name' => 'Invalid Property Access',
            'description' => 'Access to undefined or inaccessible properties',
            'severity' => Severity::High,
            'patterns' => [
                'Access to * property *',
                'Cannot access property * on *',
                'Access to an undefined property *',
                'Access to undefined property *',
                'Property * does not accept *',
                'Static property * does not exist*',
                'Access to static property * on *',
                'Property * on * is not defined*',
                'Property * in * is not readable*',
                'Property * in * is not writable*',
            ],
        ],

        'missing-model-relation' => [
            'name' => 'Missing Model Relations',
            'description' => 'References to undefined Eloquent model relations',
            'severity' => Severity::High,
            // Only Larastan's own relation rule belongs here. The undefined
            // method/property patterns this used to carry matched any class whose
            // name ended in "Model" - including Eloquent's own base class - and so
            // borrowed errors that belong to the method and property categories.
            'patterns' => [
                'Relation * is not found in * model*',
            ],
        ],

        'missing-return-statement' => [
            'name' => 'Missing Return Statements',
            'description' => 'Methods missing required return statements',
            'severity' => Severity::High,
            'patterns' => [
                '* return statement is missing*',
                'Method * should return * but return statement is missing*',
                'Function * should return * but return statement is missing*',
            ],
        ],

        'undefined-constant' => [
            'name' => 'Undefined Constants',
            'description' => 'References to undefined constants',
            'severity' => Severity::High,
            'patterns' => [
                '* undefined constant *',
                'Using * outside of class scope*',
                'Access to constant * on an unknown class *',
                'Constant * does not exist*',
                'Class constant * not found*',
            ],
        ],

        'undefined-variable' => [
            'name' => 'Undefined Variables',
            'description' => 'References to undefined variables',
            'severity' => Severity::High,
            'patterns' => [
                'Undefined variable*',
                'Variable * might not be defined*',
                'Variable * in isset* always exists*',
            ],
        ],

        // Terminal fallback. Must stay last and must stay pattern-less: it is
        // assigned explicitly when nothing else claims an error, which is what
        // guarantees no PHPStan finding is ever silently discarded. Medium keeps
        // errors we could not identify from failing a build on their own.
        self::OTHER_CATEGORY => [
            'name' => 'Other PHPStan Issues',
            'description' => 'PHPStan errors that do not map to a specific ShieldCI category',
            'severity' => Severity::Medium,
            'patterns' => [],
        ],
    ];

    /**
     * Identifier suffixes, consulted before namespace prefixes.
     *
     * For these identifiers the meaning lives in the suffix, not the namespace:
     * method.deprecated is deprecated code rather than an invalid method call, and
     * property.unused is dead code rather than invalid property access. Listed most
     * specific first.
     *
     * @var array<string, string>
     */
    private const IDENTIFIER_SUFFIX_MAP = [
        '.deprecatedAttribute' => 'deprecated-code',
        '.deprecated' => 'deprecated-code',

        '.alreadyNarrowedType' => 'dead-code',
        '.impossibleType' => 'dead-code',
        '.resultUnused' => 'dead-code',
        '.unusedType' => 'dead-code',
        '.unused' => 'dead-code',
        '.alwaysTrue' => 'dead-code',
        '.alwaysFalse' => 'dead-code',
        // The boolean family reports on one side: booleanAnd.leftAlwaysTrue etc.
        'AlwaysTrue' => 'dead-code',
        'AlwaysFalse' => 'dead-code',
    ];

    /**
     * Exact identifier to category, for members whose namespace would be wrong.
     *
     * @var array<string, string>
     */
    private const IDENTIFIER_MAP = [
        'deadCode.unreachable' => 'dead-code',
        'foreach.emptyArray' => 'dead-code',
        'catch.alreadyCaught' => 'dead-code',
        'catch.neverThrown' => 'dead-code',
        'nullsafe.neverNull' => 'dead-code',
        'isset.expr' => 'dead-code',
        'nullCoalesce.expr' => 'dead-code',
        'empty.expr' => 'dead-code',
        'property.neverRead' => 'dead-code',
        'property.neverWritten' => 'dead-code',
        'property.onlyRead' => 'dead-code',
        'property.onlyWritten' => 'dead-code',
        'return.never' => 'dead-code',
        'arrayFilter.same' => 'dead-code',
        'arrayValues.list' => 'dead-code',

        'foreach.nonIterable' => 'foreach-iterable',
        'foreach.nonIterableAtLeastOnce' => 'foreach-iterable',
        'arrayUnpacking.nonIterable' => 'foreach-iterable',

        'function.notFound' => 'invalid-function-calls',
        'function.nameCase' => 'invalid-function-calls',
        'function.void' => 'invalid-function-calls',
        'callable.nonCallable' => 'invalid-function-calls',
        'callable.notSupported' => 'invalid-function-calls',
        'callable.inaccessibleMethod' => 'invalid-function-calls',

        'class.notFound' => 'invalid-imports',
        'interface.notFound' => 'invalid-imports',
        'trait.notFound' => 'invalid-imports',
        'attribute.notFound' => 'invalid-imports',
        'typeAlias.notFound' => 'invalid-imports',
        'class.extendsInterface' => 'invalid-imports',
        'class.extendsTrait' => 'invalid-imports',
        'class.extendsEnum' => 'invalid-imports',
        'new.interface' => 'invalid-imports',
        'new.trait' => 'invalid-imports',
        'mixin.nonObject' => 'invalid-imports',

        'method.notFound' => 'invalid-method-calls',
        'method.nonObject' => 'invalid-method-calls',
        'method.private' => 'invalid-method-calls',
        'method.protected' => 'invalid-method-calls',
        'method.nonStatic' => 'invalid-method-calls',
        'method.static' => 'invalid-method-calls',
        'method.staticCall' => 'invalid-method-calls',
        'method.abstract' => 'invalid-method-calls',
        'method.nameCase' => 'invalid-method-calls',
        'method.void' => 'invalid-method-calls',
        'staticMethod.notFound' => 'invalid-method-calls',
        'staticMethod.nonObject' => 'invalid-method-calls',
        'staticMethod.private' => 'invalid-method-calls',
        'staticMethod.protected' => 'invalid-method-calls',
        'staticMethod.nameCase' => 'invalid-method-calls',
        'staticClassAccess.privateMethod' => 'invalid-method-calls',
        'argument.templateType' => 'invalid-method-calls',
        'new.abstract' => 'invalid-method-calls',
        'new.noConstructor' => 'invalid-method-calls',
        'new.static' => 'invalid-method-calls',

        'method.childParameterType' => 'invalid-method-overrides',
        'method.childReturnType' => 'invalid-method-overrides',
        'method.override' => 'invalid-method-overrides',
        'method.missingOverride' => 'invalid-method-overrides',
        'method.visibility' => 'invalid-method-overrides',
        'method.parentMethodFinal' => 'invalid-method-overrides',
        'method.parentMethodFinalByPhpDoc' => 'invalid-method-overrides',
        'method.tentativeReturnType' => 'invalid-method-overrides',
        'method.abstractOverridingNonAbstract' => 'invalid-method-overrides',
        'method.nonAbstract' => 'invalid-method-overrides',
        'method.shadowTemplate' => 'invalid-method-overrides',
        'property.override' => 'invalid-method-overrides',
        'property.missingOverride' => 'invalid-method-overrides',
        'property.parentPropertyFinal' => 'invalid-method-overrides',
        'generics.variance' => 'invalid-method-overrides',
        'generics.notSubtype' => 'invalid-method-overrides',
        'throws.notCovariant' => 'invalid-method-overrides',

        'array.invalidKey' => 'invalid-offset-access',
        'arrayUnpacking.stringOffset' => 'invalid-offset-access',
        'isset.offset' => 'invalid-offset-access',
        'nullCoalesce.offset' => 'invalid-offset-access',
        'empty.offset' => 'invalid-offset-access',
        'unset.offset' => 'invalid-offset-access',

        'isset.property' => 'invalid-property-access',
        'nullCoalesce.property' => 'invalid-property-access',
        'empty.property' => 'invalid-property-access',
        'isset.initializedProperty' => 'invalid-property-access',
        'nullCoalesce.initializedProperty' => 'invalid-property-access',
        'assign.propertyType' => 'invalid-property-access',
        'assign.propertyReadOnly' => 'invalid-property-access',
        'assign.readOnlyProperty' => 'invalid-property-access',
        'staticClassAccess.privateProperty' => 'invalid-property-access',
        'unset.readOnlyProperty' => 'invalid-property-access',
        'nullsafe.assign' => 'invalid-property-access',

        'larastan.relationExistence' => 'missing-model-relation',

        'return.missing' => 'missing-return-statement',
        'return.empty' => 'missing-return-statement',

        'staticClassAccess.privateConstant' => 'undefined-constant',

        'isset.variable' => 'undefined-variable',
        'nullCoalesce.variable' => 'undefined-variable',
        'empty.variable' => 'undefined-variable',
        'unset.variable' => 'undefined-variable',
    ];

    /**
     * Identifier namespace (the text before the first dot) to category.
     *
     * A namespace is listed here only when every member of it belongs to the same
     * category. Namespaces whose members split across categories - class, return,
     * parameter, phpDoc, isset, nullCoalesce, larastan and the rest - are left out
     * deliberately, so they fall through to the exact map, then the message
     * patterns, then Other. Under-mapping is safe because the fallback is visible;
     * over-mapping is not, because a wrong category is invisible as a mistake.
     *
     * @var array<string, string>
     */
    private const IDENTIFIER_PREFIX_MAP = [
        // Reached only when resolveCallCategory() cannot tell a function call from a
        // method call. Prefer the High category over the Critical one rather than
        // manufacture a Critical from a message we could not parse.
        'argument' => 'invalid-function-calls',
        'arguments' => 'invalid-function-calls',
        'callable' => 'invalid-function-calls',
        'function' => 'invalid-function-calls',

        'method' => 'invalid-method-calls',
        'staticMethod' => 'invalid-method-calls',
        'new' => 'invalid-method-calls',

        'property' => 'invalid-property-access',
        'staticProperty' => 'invalid-property-access',
        'propertyGetHook' => 'invalid-property-access',
        'propertySetHook' => 'invalid-property-access',

        'offsetAccess' => 'invalid-offset-access',
        'offsetAssign' => 'invalid-offset-access',

        'classConstant' => 'undefined-constant',
        'constant' => 'undefined-constant',
        'magicConstant' => 'undefined-constant',
        'outOfClass' => 'undefined-constant',

        'variable' => 'undefined-variable',

        'foreach' => 'foreach-iterable',
        'generator' => 'foreach-iterable',
    ];

    /**
     * Identifiers owned by a dedicated ShieldCI analyzer.
     *
     * Larastan enables these rules by default and PHPStanRunner includes Larastan's
     * extension, so without this list the same finding would be reported twice under
     * two different analyzer ids once the Other bucket stops discarding them.
     *
     * @var array<string>
     */
    private const IDENTIFIERS_HANDLED_ELSEWHERE = [
        'larastan.noUnnecessaryCollectionCall',
        'larastan.noEnvCallsOutsideOfConfig',
    ];

    public function __construct(
        private Config $config
    ) {}

    protected function metadata(): AnalyzerMetadata
    {
        return new AnalyzerMetadata(
            id: 'phpstan',
            name: 'PHPStan Static Analyzer',
            description: 'Comprehensive static analysis using PHPStan to detect type errors, undefined references, and code quality issues',
            category: Category::Reliability,
            severity: Severity::High,
            tags: ['phpstan', 'static-analysis', 'type-safety', 'reliability'],
            timeToFix: 120
        );
    }

    protected function runAnalysis(): ResultInterface
    {
        $basePath = $this->getBasePath();

        if ($basePath === '') {
            return $this->error('Unable to determine base path for PHPStan analysis');
        }

        $runner = new PHPStanRunner($basePath);

        // Check if PHPStan is available
        if (! $runner->isAvailable()) {
            return $this->warning(
                'PHPStan is not available',
                [$this->createIssue(
                    message: 'PHPStan binary not found',
                    location: new Location($basePath),
                    severity: Severity::Medium,
                    recommendation: 'PHPStan is included with ShieldCI. If you\'re seeing this error, ensure you\'ve run composer install to install all dependencies. If the issue persists, verify that vendor/bin/phpstan exists in your project.',
                    metadata: []
                )]
            );
        }

        // Get configuration with proper type handling
        $levelConfig = $this->config->get('shieldci.analyzers.reliability.phpstan.level', 5);
        $level = is_int($levelConfig) ? $levelConfig : (is_numeric($levelConfig) ? (int) $levelConfig : 5);

        // Use PHPStan-specific paths if configured, otherwise fall back to global paths
        $pathsConfig = $this->config->get(
            'shieldci.analyzers.reliability.phpstan.paths',
            $this->config->get('shieldci.paths.analyze', ['app'])
        );
        /** @var array<string> $paths */
        $paths = is_array($pathsConfig) ? $pathsConfig : [$pathsConfig];

        $enabledCategories = array_values(array_filter((array) $this->config->get('shieldci.analyzers.reliability.phpstan.categories', array_keys(self::ISSUE_CATEGORIES)), 'is_string'));
        $disabledCategories = array_values(array_filter((array) $this->config->get('shieldci.analyzers.reliability.phpstan.disabled_categories', []), 'is_string'));

        // Filter categories
        $activeCategories = array_values(array_diff($enabledCategories, $disabledCategories));

        // The fallback bucket is an opt-out, not an opt-in. An allow-list of known
        // categories cannot express informed consent about unknown errors, and anyone
        // who pinned a category list before this bucket existed never had the chance
        // to include it. Opt-in would leave exactly the users who configured the
        // analyzer still losing findings.
        if (! in_array(self::OTHER_CATEGORY, $disabledCategories, true)
            && ! in_array(self::OTHER_CATEGORY, $activeCategories, true)) {
            $activeCategories[] = self::OTHER_CATEGORY;
        }

        $timeoutConfig = $this->config->get('shieldci.timeout', 300);
        $timeout = is_int($timeoutConfig) ? $timeoutConfig : (is_numeric($timeoutConfig) ? (int) $timeoutConfig : 300);

        $memoryLimitConfig = $this->config->get('shieldci.memory_limit');
        $memoryLimit = is_string($memoryLimitConfig) && $memoryLimitConfig !== '' ? $memoryLimitConfig : null;

        try {
            // Run PHPStan once on all paths
            $runner->analyze($paths, $level, $timeout, $memoryLimit);

            // An error PHPStan could not attach to a file is still a failed analysis
            $analysisErrors = $runner->getAnalysisErrors();

            // Categorize all issues
            $categorizedIssues = $this->categorizeIssues($runner->getIssues(), $activeCategories);
        } catch (\Throwable $e) {
            return $this->error(
                sprintf('PHPStan analysis failed: %s', $e->getMessage()),
                [
                    'exception' => get_class($e),
                    'error_message' => $e->getMessage(),
                ]
            );
        }

        // Exact, not double-counted: categorizeIssues() assigns each issue to exactly
        // one category, so the categories partition the issue set.
        $totalIssues = array_sum(array_map(fn ($issues) => $issues->count(), $categorizedIssues));

        if ($totalIssues === 0) {
            return $this->noFileIssuesResult($analysisErrors);
        }

        // Create issue objects for each category
        $allIssueObjects = [];
        foreach ($categorizedIssues as $category => $issues) {
            if ($issues->isEmpty()) {
                continue;
            }

            $categoryConfig = self::ISSUE_CATEGORIES[$category];
            $issueObjects = $this->createIssuesFromPHPStanResults(
                $issues,
                $categoryConfig['name'].' detected',
                $categoryConfig['severity'],
                fn (string $message) => $this->getRecommendation($category, $message)
            );

            $allIssueObjects = array_merge($allIssueObjects, $issueObjects);
        }

        if ($allIssueObjects === []) {
            return $this->noFileIssuesResult($analysisErrors);
        }

        $displayedCount = count($allIssueObjects);
        $message = $this->formatIssueCountMessage($totalIssues, $displayedCount, 'PHPStan issue(s)');

        // The per-category display cap can hide rows, so publish the true breakdown.
        // This is what keeps the Other bucket countable even when its rows are
        // truncated away, and is the machine-readable half of "nothing is discarded".
        $metadata = [
            'total_issues' => $totalIssues,
            'displayed_issues' => $displayedCount,
            'issues_by_category' => array_map(
                static fn (Collection $issues): int => $issues->count(),
                $categorizedIssues
            ),
            'truncated' => $displayedCount < $totalIssues,
        ];

        // Both halves are real findings, so neither displaces the other: the status stays
        // severity-derived and the analysis errors ride along instead of being dropped.
        // PHPStan throws away the file results when it hits an internal error, so findings
        // that arrive next to one are a partial view and have to say so.
        if ($analysisErrors !== []) {
            $message .= sprintf(
                '. PHPStan also reported %d analysis error(s), so these findings may be incomplete: %s',
                count($analysisErrors),
                $this->summarizeAnalysisErrors($analysisErrors)
            );

            $metadata['analysis_errors'] = $analysisErrors;
        }

        return $this->resultBySeverity($message, $allIssueObjects, $metadata);
    }

    /**
     * Result for a run that produced no reportable file issues.
     *
     * PHPStan can come back with an empty "files" map and still have failed: unmatched
     * ignoreErrors patterns, unusable ignore configuration and internal errors are all
     * reported outside the per-file map, and an aborted run reports nothing at all.
     * Calling either of those "passed" claims a clean analysis that never happened.
     *
     * @param  list<string>  $analysisErrors
     */
    private function noFileIssuesResult(array $analysisErrors): ResultInterface
    {
        if ($analysisErrors === []) {
            return $this->passed('No PHPStan issues detected');
        }

        return $this->error(
            sprintf(
                'PHPStan reported %d analysis error(s): %s',
                count($analysisErrors),
                $this->summarizeAnalysisErrors($analysisErrors)
            ),
            ['analysis_errors' => $analysisErrors]
        );
    }

    /**
     * Condense analysis errors into one bounded clause for a result message.
     *
     * A reportUnmatchedIgnoredErrors run can produce dozens of these. The full list always
     * reaches the caller through the analysis_errors metadata key; the message quotes the
     * leaders and counts the rest.
     *
     * @param  list<string>  $analysisErrors
     */
    private function summarizeAnalysisErrors(array $analysisErrors): string
    {
        $quoted = array_slice($analysisErrors, 0, self::MAX_ANALYSIS_ERRORS_IN_MESSAGE);
        $summary = implode(' | ', $quoted);
        $remaining = count($analysisErrors) - count($quoted);

        if ($remaining > 0) {
            $summary .= sprintf(' (and %d more)', $remaining);
        }

        return $summary;
    }

    /**
     * Assign every PHPStan issue to exactly one category.
     *
     * Classification is a pure function of the issue and is deliberately independent
     * of configuration: an issue resolves to the same category whether or not the
     * user has that category enabled, and enabled/disabled is applied afterwards as
     * a filter. That ordering is what keeps disabled_categories meaning "do not
     * report these" rather than "relabel these as Other".
     *
     * Because each issue is appended to exactly one bucket, the categories partition
     * the issue set and summing their counts is exact by construction.
     *
     * @param  Collection<int, PHPStanIssue>  $issues
     * @param  array<string>  $activeCategories
     * @return array<string, Collection<int, PHPStanIssue>>
     */
    private function categorizeIssues(Collection $issues, array $activeCategories): array
    {
        /** @var array<string, list<PHPStanIssue>> $buckets */
        $buckets = [];

        foreach ($issues as $issue) {
            $identifier = $issue['identifier'] ?? null;

            if ($identifier !== null && in_array($identifier, self::IDENTIFIERS_HANDLED_ELSEWHERE, true)) {
                continue;
            }

            $category = $this->resolveCategory($identifier, $issue['message']);

            if (! in_array($category, $activeCategories, true)) {
                continue;
            }

            $buckets[$category][] = $issue;
        }

        // Emit in declaration order rather than the order PHPStan happened to visit
        // files, so the report is stable across runs.
        $ordered = [];

        foreach (array_keys(self::ISSUE_CATEGORIES) as $key) {
            if (isset($buckets[$key])) {
                $ordered[$key] = collect($buckets[$key]);
            }
        }

        return $ordered;
    }

    /**
     * Resolve exactly one category for an issue.
     *
     * Never returns null: anything unclassifiable lands in self::OTHER_CATEGORY, so
     * an error can no longer be discarded by failing to match.
     */
    private function resolveCategory(?string $identifier, string $message): string
    {
        if ($identifier !== null) {
            $category = $this->categoryFromIdentifier($identifier, $message);

            if ($category !== null) {
                return $category;
            }
        }

        return $this->categoryFromMessage($message) ?? self::OTHER_CATEGORY;
    }

    /**
     * Classify by PHPStan's stable error identifier, most specific rule first.
     *
     * Returns null when no rule applies, so the caller falls back to the message
     * patterns rather than jumping straight to Other - that is what preserves the
     * previous behaviour for identifiers we deliberately do not map.
     */
    private function categoryFromIdentifier(string $identifier, string $message): ?string
    {
        if (isset(self::IDENTIFIER_MAP[$identifier])) {
            return self::IDENTIFIER_MAP[$identifier];
        }

        foreach (self::IDENTIFIER_SUFFIX_MAP as $suffix => $category) {
            if (str_ends_with($identifier, $suffix)) {
                return $category;
            }
        }

        // PHPStan reuses the argument identifiers for function, method, static
        // method, constructor and callable calls alike, so only the message can say
        // which category an argument error belongs to.
        if (str_starts_with($identifier, 'argument.') || $identifier === 'arguments.count') {
            $resolved = $this->resolveCallCategory($message);

            if ($resolved !== null) {
                return $resolved;
            }
        }

        $dot = strpos($identifier, '.');

        if ($dot === false) {
            return null;
        }

        return self::IDENTIFIER_PREFIX_MAP[substr($identifier, 0, $dot)] ?? null;
    }

    /**
     * Classify by message pattern, first match wins in declaration order.
     *
     * Retained for PHPStan below 1.11, which emits no identifiers at all, and for
     * third-party rules that set none.
     */
    private function categoryFromMessage(string $message): ?string
    {
        foreach (self::ISSUE_CATEGORIES as $category => $config) {
            if (isset($config['regex']) && preg_match($config['regex'], $message) === 1) {
                return $category;
            }

            if ($config['patterns'] !== []
                && PHPStanRunner::matchesAnyPattern($message, $config['patterns'])) {
                return $category;
            }
        }

        return null;
    }

    /**
     * Tell a function-like call from a method-like one for the shared argument
     * identifiers.
     *
     * PHPStan builds these messages from fixed literals per rule class, so the
     * wording is a reliable discriminator: "of function" / "of method" /
     * "of static method" / "constructor" / "of callable", and the matching
     * "Function X invoked with" / "Method X::y() invoked with" forms.
     *
     * Returns null when the shape is unrecognised so the caller falls through
     * instead of guessing.
     */
    private function resolveCallCategory(string $message): ?string
    {
        foreach ([' of method ', ' of static method ', ' constructor '] as $needle) {
            if (str_contains($message, $needle)) {
                return 'invalid-method-calls';
            }
        }

        foreach (['Method ', 'Static method ', 'Class '] as $prefix) {
            if (str_starts_with($message, $prefix)) {
                return 'invalid-method-calls';
            }
        }

        foreach ([' of function ', ' of callable ', ' of closure '] as $needle) {
            if (str_contains($message, $needle)) {
                return 'invalid-function-calls';
            }
        }

        foreach (['Function ', 'Callable ', 'Closure '] as $prefix) {
            if (str_starts_with($message, $prefix)) {
                return 'invalid-function-calls';
            }
        }

        return null;
    }

    /**
     * Get recommendation message based on category and PHPStan message.
     */
    private function getRecommendation(string $category, string $message): string
    {
        // The fallback bucket has no keyword table by definition - these are the
        // errors we could not identify - so say what is actually known and let
        // PHPStan's own message and tip carry the detail.
        if ($category === self::OTHER_CATEGORY) {
            return 'Review this PHPStan error directly. ShieldCI has no specific guidance for it, '
                .'so consult the PHPStan documentation for the rule that reported it. '
                .'PHPStan message: '.$message;
        }

        $recommendations = [
            'dead-code' => [
                'Unreachable statement' => 'Remove unreachable code - this statement will never be executed. Check for early returns, throws, or exits before this code.',
                'is unused' => 'Remove unused code - this variable, parameter, or import is never used. Clean up your code by removing it.',
                'does not do anything' => 'This statement has no effect - it does not modify state or return a value. Either use the result or remove the statement.',
                'always' => 'Remove redundant condition - this expression always evaluates to the same value. Simplify your logic or remove the dead branch.',
            ],
            'deprecated-code' => [
                'method' => 'Replace deprecated method - this method is marked as deprecated and may be removed in future versions. Check the documentation for the recommended alternative.',
                'class' => 'Replace deprecated class/interface - this type is marked as deprecated. Migrate to the recommended alternative to ensure compatibility with future versions.',
                'function' => 'Replace deprecated function - this function is marked as deprecated. Use the recommended alternative function.',
                'constant' => 'Replace deprecated constant - this constant is marked as deprecated. Use the recommended alternative constant.',
            ],
            'foreach-iterable' => [
                'invalid type' => 'Fix the foreach loop - the variable being iterated is not of an iterable type. Ensure the variable is an array, Traversable, or Iterator before using it in a foreach loop.',
                'Cannot use' => 'Fix the foreach loop - the value cannot be used in a foreach loop. Check the type of the variable and ensure it implements Traversable or is an array.',
                'does not specify' => 'Fix the foreach loop - the type does not specify that it is iterable. Add proper type hints or ensure the variable is iterable before using it in a foreach loop.',
            ],
            'invalid-function-calls' => [
                'not found' => 'Fix the function call - the function does not exist. Check for typos in the function name or ensure the function is defined.',
                'Parameter' => 'Fix the function parameters - they do not match the function signature. Check the parameter types, order, and count.',
            ],
            'invalid-imports' => [
                'not found' => 'Fix the import - the class, interface, or trait does not exist. Check for typos in the import statement or ensure the file exists.',
            ],
            'invalid-method-calls' => [
                'Eloquent\Builder' => 'Fix the method call - if this is an Eloquent local scope, narrow the Builder type with an inline @var annotation: /** @var \Illuminate\Database\Eloquent\Builder<\App\Models\YourModel> $query */. This is the simplest fix when calling scopes inside closures. Alternatively, add a @method annotation to the model: /** @method static \Illuminate\Database\Eloquent\Builder<static> sent() */. ShieldCI includes Larastan which recognizes most scopes automatically, but scopes inside closures, traits, or parent models may need these annotations.',
                'undefined method' => 'Fix the method call - the method does not exist on this class. Check for typos in the method name or ensure the method is defined.',
                'Parameter' => 'Fix the method parameters - they do not match the method signature. Check the parameter types, order, and count.',
                'private' => 'Fix the method visibility - you are calling a private/protected method outside its scope.',
                'protected' => 'Fix the method visibility - you are calling a private/protected method outside its scope.',
            ],
            'invalid-method-overrides' => [
                'covariant' => 'Fix the method override - the return type is not covariant with the parent method. Ensure the return type is compatible.',
                'contravariant' => 'Fix the method override - the parameter type is not contravariant with the parent method. Ensure the parameter type is compatible.',
                'visibility' => 'Fix the method override - you cannot change method visibility when overriding. Use the same visibility as the parent method.',
            ],
            'invalid-offset-access' => [
                'does not exist' => 'Fix the offset access - the offset does not exist on this array or object. Check the offset key or ensure it exists before accessing.',
                'might not exist' => 'Fix the offset access - the offset might not exist. Add an isset() check before accessing the offset.',
            ],
            'invalid-property-access' => [
                'Access to an undefined property' => 'Fix the property access - the property does not exist on this class. If this is an Eloquent Attribute accessor, add a generic return type PHPDoc: /** @return Attribute<string, never> */. Larastan requires generic Attribute<TGet, TSet> annotations to recognize accessor-defined properties.',
                'undefined property' => 'Fix the property access - the property does not exist on this class. Check for typos in the property name or ensure the property is defined.',
                'private' => 'Fix the property visibility - you are accessing a private/protected property outside its scope.',
                'protected' => 'Fix the property visibility - you are accessing a private/protected property outside its scope.',
            ],
            'missing-model-relation' => [
                'not found' => 'Fix the model relation - the relation does not exist on this model. Ensure the relation method is defined in the model.',
            ],
            'missing-return-statement' => [
                'return statement is missing' => 'Add a return statement - this method is expected to return a value but is missing a return statement.',
            ],
            'undefined-constant' => [
                'undefined constant' => 'Fix the constant reference - the constant does not exist. Check for typos in the constant name or ensure the constant is defined.',
            ],
            'undefined-variable' => [
                'Undefined variable' => 'Fix the variable reference - the variable is used before it is defined. Ensure the variable is initialized before use.',
                'might not be defined' => 'Fix the variable reference - the variable might not be defined in all code paths. Ensure the variable is initialized in all branches.',
            ],
        ];

        // Try to find a specific recommendation
        if (isset($recommendations[$category])) {
            foreach ($recommendations[$category] as $keyword => $recommendation) {
                if (str_contains($message, $keyword)) {
                    return $recommendation.' PHPStan message: '.$message;
                }
            }
        }

        // Fallback to generic recommendation
        $categoryName = self::ISSUE_CATEGORIES[$category]['name'] ?? 'issue';

        return 'Fix the '.$categoryName.' detected by PHPStan. PHPStan message: '.$message;
    }
}
