from numbers import Integral

MODULUS = 0x11B

def _element(value):
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise TypeError("Field elements must be integers, not bools.")
    value = int(value)
    if not 0 <= value <= 255:
        raise ValueError("Field elements must be in 0..255.")
    return value

def _vector(values):
    return [_element(value) for value in values]

def _rows(matrix_rows):
    rows = [_vector(row) for row in matrix_rows]
    if rows:
        width = len(rows[0])
        if width == 0 or any(len(row) != width for row in rows):
            raise ValueError("Matrix must be rectangular with nonempty rows.")
    return rows

def _mul(left, right):
    product = 0
    for bit_index in range(8):
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x100:
            left ^= MODULUS
        right >>= 1
    return product

def gf_add(left, right):
    return _element(left) ^ _element(right)

def gf_mul(left, right):
    return _mul(_element(left), _element(right))

def gf_pow(value, exponent):
    value = _element(value)
    if isinstance(exponent, bool) or not isinstance(exponent, Integral):
        raise TypeError("Exponent must be an integer.")
    if exponent < 0:
        raise ValueError("Exponent must be nonnegative.")
    exponent = int(exponent)
    result = 1
    while exponent:
        if exponent & 1:
            result = _mul(result, value)
        value = _mul(value, value)
        exponent >>= 1
    return result

def gf_inv(value):
    value = _element(value)
    if value == 0:
        raise ZeroDivisionError("Zero has no multiplicative inverse.")
    return gf_pow(value, 254)

def gf_dot(left, right):
    left, right = _vector(left), _vector(right)
    if len(left) != len(right):
        raise ValueError("Vectors must have the same length.")
    result = 0
    for left_value, right_value in zip(left, right):
        result ^= _mul(left_value, right_value)
    return result

def gf_matvec(matrix_rows, vector):
    rows, vector = _rows(matrix_rows), _vector(vector)
    if not vector:
        raise ValueError("Vector must be nonempty.")
    if rows and len(rows[0]) != len(vector):
        raise ValueError("Matrix/vector dimensions do not match.")
    return [gf_dot(row, vector) for row in rows]

def _rref(matrix, coefficient_columns):
    reduced = [row[:] for row in matrix]
    pivots = []
    pivot_row = 0

    for column in range(coefficient_columns):
        if pivot_row == len(reduced):
            break

        candidate = next(
            (index for index in range(pivot_row, len(reduced))
             if reduced[index][column] != 0), None
        )

        if candidate is None:
            continue

        reduced[pivot_row], reduced[candidate] = reduced[candidate], reduced[pivot_row]
        inverse = gf_inv(reduced[pivot_row][column])
        reduced[pivot_row] = [_mul(value, inverse) for value in reduced[pivot_row]]

        for index in range(len(reduced)):
            if index == pivot_row:
                continue

            factor = reduced[index][column]
            if factor:
                reduced[index] = [
                    value ^ _mul(factor, pivot_value)
                    for value, pivot_value in zip(reduced[index], reduced[pivot_row])
                ]

        pivots.append(column)
        pivot_row += 1

    return reduced, pivots

def gf_rank(matrix_rows):
    rows = _rows(matrix_rows)
    if not rows:
        return 0
    return len(_rref(rows, len(rows[0]))[1])

def gf_solve(matrix_rows, target):
    'Solve matrix_rows.T @ weights = target; free variables are zero.'
    rows, target = _rows(matrix_rows), _vector(target)

    if not target:
        raise ValueError("Target must be nonempty.")

    dimension = len(target)
    if rows and len(rows[0]) != dimension:
        raise ValueError("Row width must equal target length.")

    row_count = len(rows)
    if row_count == 0:
        return [] if not any(target) else None

    augmented = [
        [rows[index][column] for index in range(row_count)] + [target[column]]
        for column in range(dimension)
    ]

    reduced, pivots = _rref(augmented, row_count)

    for equation in reduced:
        if not any(equation[:row_count]) and equation[row_count] != 0:
            return None

    weights = [0] * row_count
    for equation_index, pivot_column in enumerate(pivots):
        weights[pivot_column] = reduced[equation_index][row_count]

    return weights
